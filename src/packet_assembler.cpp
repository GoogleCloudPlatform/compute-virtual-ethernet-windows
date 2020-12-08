// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "packet_assembler.h"  // NOLINT: include directory

#include <ndis.h>

#include "offload.h"             // NOLINT: include directory
#include "rx_packet.h"           // NOLINT: include directory
#include "trace.h"               // NOLINT: include directory
#include "utils.h"               // NOLINT: include directory

#include "packet_assembler.tmh"  // NOLINT: trace message header

namespace {
// Internet Header Length (IHL) value for ip header without options.
// It is the number of 32-bit works. so 5 means 20 bytes.
constexpr UINT kIpv4HeaderNoOptionLength = 5;

// Data offset value for tcp header without options.
// It is the number of 32-bit works. so 5 means 20 bytes.
constexpr UINT kTcpHeaderNoOptionDataOffset = 5;

// TCP packet header total length.
// 14 (Eth_header) + 20 (IP_header) + 20(TCP_header)
constexpr UINT kEthIpv4TcpHeaderTotalLength = 54;

// TCP packet header total length exclude Ethernet header..
// 20 (IP_header) + 20(TCP_header)
constexpr UINT kIpv4TcpHeaderTotalLength = 40;

constexpr UINT kAcceptableTcpFlagMask = (kTcpFlagACK | kTcpFlagPSH);

// This assumes no option fields in both ip and tcp header.
UINT GetPayloadLengthFromRxPacket(const RxPacket& rx_packet) {
  return rx_packet.packet_length() - kEthIpv4TcpHeaderTotalLength;
}

#ifdef SUPPORT_RSC
// Check the header of the packet.
// Return true it rx_packet is a candidate for merge and false otherwise.
bool IsHeaderValid(const RxPacket& rx_packet) {
  // Require TCP/IP packet.
  if (!rx_packet.is_ipv4() || !rx_packet.is_tcp()) {
    return false;
  }

  // Require no option fields in IP header.
  if (!(rx_packet.ipv4_header()->internet_header_length ==
        kIpv4HeaderNoOptionLength)) {
    return false;
  }

  // Require no option fields in TCP header.
  // TODO(b/140896200): Allow TCP timestamp option.
  const TcpHeader* tcp_header = rx_packet.tcp_header();
  if (!(tcp_header->data_offset == kTcpHeaderNoOptionDataOffset)) {
    return false;
  }

  // Require checksum validated.
  NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO checksum_info =
      rx_packet.checksum_info();
  if (!(checksum_info.Receive.IpChecksumSucceeded &&
        checksum_info.Receive.TcpChecksumSucceeded)) {
    return false;
  }

  // Only PSH AND ACK flag can be set.
  if ((tcp_header->flags & (~kAcceptableTcpFlagMask)) != 0) {
    return false;
  }

  // The packet needs to have payload.
  // TODO(b/174526031): Support pure ACK packet coalescing.
  if (rx_packet.packet_length() == kEthIpv4TcpHeaderTotalLength) {
    return false;
  }

  return true;
}

bool IsSegmentCoalescePossible(const RxPacket& rx_packet,
                               const NetBufferListContainer& target_container) {
  // Verify the last packet is a candidate for coalescing.
  if (!target_container.HasValidCoalescedUnit()) {
    return false;
  }

  // Check IP addresses.
  const IPv4Header* candidate_ip_header = rx_packet.ipv4_header();
  const IPv4Header* current_ip_header =
      target_container.coalesced_unit_ipv4_header();
  if (candidate_ip_header->source_address !=
          current_ip_header->source_address ||
      candidate_ip_header->dest_address != current_ip_header->dest_address) {
    return false;
  }

  // Check port number.
  const TcpHeader* candidate_tcp_header = rx_packet.tcp_header();
  const TcpHeader* current_tcp_header =
      target_container.coalesced_unit_tcp_header();
  if (candidate_tcp_header->source_port != current_tcp_header->source_port ||
      candidate_tcp_header->dest_port != current_tcp_header->dest_port) {
    return false;
  }

  // Check sequence number is expected.
  if (RtlUlongByteSwap(candidate_tcp_header->seq_number) !=
      target_container.coalesced_unit_next_seq_num()) {
    return false;
  }

  // Check total size is smaller than max.
  UINT data_payload_length = GetPayloadLengthFromRxPacket(rx_packet);
  if (target_container.coalesced_unit_packet_length() + data_payload_length >
      kMaxPacketSize) {
    return false;
  }

  return true;
}
#endif  // SUPPORT_RSC

}  // namespace

void NetBufferListContainer::AddNetBufferList(NET_BUFFER_LIST* net_buffer_list,
                                              const RxPacket& rx_packet,
                                              bool is_coalescing_candidate) {
  if (head_ == nullptr) {
    head_ = net_buffer_list;
    tail_ = net_buffer_list;
  } else {
    NET_BUFFER_LIST_NEXT_NBL(tail_) = net_buffer_list;
    tail_ = net_buffer_list;
  }
  count_++;

#ifdef SUPPORT_RSC
  if (HasValidCoalescedUnit()) {
    ClearCoalescedUnit();
  }

  if (is_coalescing_candidate) {
    // Init coalesced_unit
    coalesced_unit_.is_valid = true;
    coalesced_unit_.count = 1;
    coalesced_unit_.ipv4_header = rx_packet.ipv4_header();
    coalesced_unit_.net_buffer = NET_BUFFER_LIST_FIRST_NB(tail_);
    coalesced_unit_.current_mdl =
        NET_BUFFER_CURRENT_MDL(coalesced_unit_.net_buffer);
    coalesced_unit_.packet_length = rx_packet.packet_length();

    TcpHeader* tcp_header = rx_packet.tcp_header();
    coalesced_unit_.tcp_header = tcp_header;

    UINT data_payload_length = GetPayloadLengthFromRxPacket(rx_packet);
    coalesced_unit_.next_seq_num =
        RtlUlongByteSwap(tcp_header->seq_number) + data_payload_length;
  }
#else
  UNREFERENCED_PARAMETER(rx_packet);
  UNREFERENCED_PARAMETER(is_coalescing_candidate);
#endif
}

#ifdef SUPPORT_RSC
void NetBufferListContainer::ExtendCoalecedUnit(MDL* mdl,
                                                UINT data_payload_length,
                                                const TcpHeader& tcp_header) {
  NT_ASSERT(HasValidCoalescedUnit());

  // Add mdl to the linked list.
  coalesced_unit_.current_mdl->Next = mdl;
  coalesced_unit_.current_mdl = mdl;
  coalesced_unit_.count++;

  // Add data payload size to total size.
  NT_ASSERT(coalesced_unit_.packet_length + data_payload_length <=
            kMaxPacketSize);
  coalesced_unit_.packet_length += data_payload_length;

  // Adjust next expected seq num in tcp header.
  coalesced_unit_.next_seq_num += data_payload_length;

  // Adjust NET_BUFFER LENGTH.
  NET_BUFFER_DATA_LENGTH(coalesced_unit_.net_buffer) =
      coalesced_unit_.packet_length;
  // Adjust total length in ip_header.
  coalesced_unit_.ipv4_header->total_length =
      RtlUshortByteSwap(coalesced_unit_.packet_length - kEthHeaderSize);

  // Carry over ACK, FLAG and Window size
  coalesced_unit_.tcp_header->window = tcp_header.window;
  coalesced_unit_.tcp_header->ack_number = tcp_header.ack_number;
  coalesced_unit_.tcp_header->flags |= tcp_header.flags;

  // Update NBL coalesed seg count.
  NET_BUFFER_LIST_COALESCED_SEG_COUNT(tail_) = coalesced_unit_.count;
}
#endif

inline void NetBufferListContainer::ClearCoalescedUnit() {
  coalesced_unit_ = {};
}

bool PacketAssembler::CanAllocateNBL() {
  return num_nbls_ != max_nbls_to_indicate_;
}

NET_BUFFER_LIST* PacketAssembler::ProcessAsyncPacket(RxPacket* rx_packet) {
  return ProcessPacket(rx_packet, &async_net_buffer_list_);
}

NET_BUFFER_LIST* PacketAssembler::ProcessSyncPacket(RxPacket* rx_packet) {
  return ProcessPacket(rx_packet, &sync_net_buffer_list_);
}

NET_BUFFER_LIST* PacketAssembler::ProcessPacket(
    RxPacket* rx_packet, NetBufferListContainer* nbl_container) {
  statistics_->AddReceivedPacket(rx_packet->packet_length(),
                                 rx_packet->eth_header());
#ifdef SUPPORT_RSC
  // If there is no need to coalesce, just create NBL for each packet.
  if (!segment_coalescing_enabled_) {
    return AllocateNewNBL(rx_packet, nbl_container,
                          /*is_coalescing_candidate=*/false);
  }

  // Start coalescing process:
  // 1. Verify the packet is a candidate for coalescing from the header.
  if (!IsHeaderValid(*rx_packet)) {
    return AllocateNewNBL(rx_packet, nbl_container,
                          /*is_coalescing_candidate=*/false);
  }

  // 2. Try to coalesce with previous NBL.
  if (!IsSegmentCoalescePossible(*rx_packet, *nbl_container)) {
    // At this step, rx_packet is a valid coalescing candidate.
    return AllocateNewNBL(rx_packet, nbl_container,
                          /*is_coalescing_candidate=*/true);
  }

  // 3. allocate mdl and merge with previous one.
  MergePackets(*rx_packet, nbl_container);
  return nbl_container->tail();
#else
  return AllocateNewNBL(rx_packet, nbl_container,
                        /*is_coalescing_candidate=*/false);
#endif  // SUPPORT_RSC
}

void PacketAssembler::ReportPackets(NDIS_HANDLE miniport_handle) {
  if (async_net_buffer_list_.count() != 0) {
    ReportReceiveNetBufferList(miniport_handle, async_net_buffer_list_.head(),
                               async_net_buffer_list_.count(),
                               NDIS_RECEIVE_FLAGS_DISPATCH_LEVEL);
  }

  if (sync_net_buffer_list_.count() != 0) {
    ReportReceiveNetBufferList(
        miniport_handle, sync_net_buffer_list_.head(),
        sync_net_buffer_list_.count(),
        NDIS_RECEIVE_FLAGS_DISPATCH_LEVEL | NDIS_RECEIVE_FLAGS_RESOURCES);
  }
}

void PacketAssembler::ReportReceiveNetBufferList(
    NDIS_HANDLE miniport_handle, NET_BUFFER_LIST* net_buffer_list,
    UINT32 num_net_buffer_list, ULONG receive_flag) {
  NdisMIndicateReceiveNetBufferLists(miniport_handle, net_buffer_list,
                                     /*PortNumber=*/0, num_net_buffer_list,
                                     receive_flag);

  // Release the net_buffer_list if packets are handled synchronously.
  if (receive_flag & NDIS_RECEIVE_FLAGS_RESOURCES) {
    while (net_buffer_list != nullptr) {
      NET_BUFFER_LIST* nbl_to_free = net_buffer_list;
      net_buffer_list = NET_BUFFER_LIST_NEXT_NBL(net_buffer_list);
      NET_BUFFER_LIST_NEXT_NBL(nbl_to_free) = nullptr;

      FreeMdlsFromReceiveNetBuffer(NET_BUFFER_LIST_FIRST_NB(nbl_to_free));
    }
  }
}

NET_BUFFER_LIST* PacketAssembler::AllocateNewNBL(
    RxPacket* rx_packet, NetBufferListContainer* nbl_container,
    bool is_coalescing_candidate) {
  NT_ASSERT(CanAllocateNBL());

  MDL* mdl = NdisAllocateMdl(miniport_handle_, rx_packet->eth_header(),
                             rx_packet->packet_length());

  if (mdl == nullptr) {
    DEBUGP(GVNIC_ERROR, "[%s]: Allocate Mdl failed.", __FUNCTION__);
    return nullptr;
  }

  NET_BUFFER_LIST* net_buffer_list = rx_packet->net_buffer_list();
  NET_BUFFER* net_buffer = NET_BUFFER_LIST_FIRST_NB(net_buffer_list);

  NT_ASSERT(NET_BUFFER_FIRST_MDL(net_buffer) == nullptr);
  NT_ASSERT(NET_BUFFER_CURRENT_MDL(net_buffer) == nullptr);

  NET_BUFFER_FIRST_MDL(net_buffer) = mdl;
  NET_BUFFER_DATA_LENGTH(net_buffer) = rx_packet->packet_length();
  NET_BUFFER_CURRENT_MDL(net_buffer) = mdl;

  // Apply checksum and rss info if needed.
  if (rx_packet->is_checksum_offload()) {
    auto csum_info = rx_packet->checksum_info();

#ifdef SUPPORT_RSC
    if (is_coalescing_candidate) {
      csum_info.Receive.IpChecksumValueInvalid = true;
      csum_info.Receive.TcpChecksumValueInvalid = true;
    }
#endif  // SUPPORT_RSC
    NET_BUFFER_LIST_INFO(net_buffer_list, TcpIpChecksumNetBufferListInfo) =
        csum_info.Value;
  }

  // Apply RSS
  if (rx_packet->is_rss_offload()) {
    NET_BUFFER_LIST_SET_HASH_VALUE(net_buffer_list,
                                   rx_packet->rss_hash_value());
    NET_BUFFER_LIST_SET_HASH_FUNCTION(net_buffer_list,
                                      rx_packet->rss_hash_func());
    UINT32 rss_hash_type = rx_packet->rss_hash_type();

    if (rx_packet->is_tcp() && (rss_hash_type & NDIS_HASH_TCP_IPV4)) {
      NET_BUFFER_LIST_SET_HASH_TYPE(net_buffer_list, NDIS_HASH_TCP_IPV4);
    } else if (rx_packet->is_udp() && (rss_hash_type & NDIS_HASH_UDP_IPV4)) {
      NET_BUFFER_LIST_SET_HASH_TYPE(net_buffer_list, NDIS_HASH_UDP_IPV4);
    } else {
      NET_BUFFER_LIST_SET_HASH_TYPE(net_buffer_list, NDIS_HASH_IPV4);
    }
  }

  // Add it to the container.
  nbl_container->AddNetBufferList(net_buffer_list, *rx_packet,
                                  is_coalescing_candidate);

  num_nbls_++;
  return net_buffer_list;
}

#ifdef SUPPORT_RSC
void PacketAssembler::MergePackets(const RxPacket& rx_packet,
                                   NetBufferListContainer* nbl_container) {
  // Extend current coalesced unit.
  UINT payload_length = GetPayloadLengthFromRxPacket(rx_packet);
  MDL* payload_mdl = NdisAllocateMdl(
      miniport_handle_,
      OffsetToPointer(rx_packet.eth_header(), kEthIpv4TcpHeaderTotalLength),
      payload_length);
  nbl_container->ExtendCoalecedUnit(payload_mdl, payload_length,
                                    *rx_packet.tcp_header());
  DEBUGP(GVNIC_VERBOSE, "[%s] TCP packet merged", __FUNCTION__);

  // TODO: handle TCP timestamp option.
}
#endif  // SUPPORT_RSC
