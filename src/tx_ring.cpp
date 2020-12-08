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

#include "tx_ring.h"  // NOLINT: include directory

#include <ndis.h>

#include "abi.h"                 // NOLINT: include directory
#include "adapter_resource.h"    // NOLINT: include directory
#include "adapter_statistics.h"  // NOLINT: include directory
#include "admin_queue.h"         // NOLINT: include directory
#include "netutils.h"            // NOLINT: include directory
#include "ring_base.h"           // NOLINT: include directory
#include "spin_lock_context.h"   // NOLINT: include directory
#include "trace.h"               // NOLINT: include directory
#include "tx_net_buffer.h"       // NOLINT: include directory
#include "utils.h"               // NOLINT: include directory

#include "tx_ring.tmh"  // NOLINT: trace message header

bool TxRing::Init(UINT32 id, UINT32 slice, UINT32 traffic_class,
                  UINT32 num_descriptor, bool use_raw_addressing,
                  QueuePageList* queue_page_list, UINT32 notify_id,
                  AdapterResources* adapter_resource,
                  AdapterStatistics* statistics,
                  const DeviceCounter* device_counters) {
  PAGED_CODE();

  NdisAllocateSpinLock(&lock_);

  // num_descriptor is expected to be power of 2.
  if ((num_descriptor & (num_descriptor - 1)) != 0) {
    DEBUGP(GVNIC_ERROR,
           "Error: [%s] Number of descriptors must be a power of 2, but is "
           "instead %u.",
           __FUNCTION__, num_descriptor_);
    NT_ASSERT((num_descriptor & (num_descriptor - 1)) == 0);
    return false;
  }

  num_request_segments_ = 0;
  num_sent_segments_ = 0;
  num_descriptor_ = num_descriptor;
  descriptor_mask_ = num_descriptor_ - 1;
  eth_header_len_.IPv4 = eth_header_len_.IPv6 = kEthAddrLen;

  DEBUGP(GVNIC_INFO, "[%s] Allocating resource for tx: %u with %u descriptors",
         __FUNCTION__, id, num_descriptor_);

  if (!RingBase::Init(id, slice, traffic_class, use_raw_addressing,
                      queue_page_list, notify_id, adapter_resource, statistics,
                      device_counters)) {
    return false;
  }

  if (!descriptor_ring_.Allocate(miniport_handle(), num_descriptor_)) {
    DEBUGP(GVNIC_ERROR,
           "[%s] ERROR: Memory allocation failed for tx descriptor ring",
           __FUNCTION__);
    return false;
  }

  return true;
}

void TxRing::Release() {
  PAGED_CODE();
  descriptor_ring_.Release();
  RingBase::Release();
  NdisFreeSpinLock(&lock_);
}

TxNetBufferList* TxRing::GetTxNetBufferList(PNET_BUFFER_LIST net_buffer_list) {
  TxNetBufferList* net_packet =
      AllocateMemory<TxNetBufferList>(miniport_handle());
  if (!net_packet) {
    return nullptr;
  }

  net_packet->status = NDIS_STATUS_SUCCESS;
  net_packet->net_buffer_list = net_buffer_list;

  // Extract Checksum, lso info as it is common for all net_buffers inside.
  net_packet->checksum_info.Value =
      NET_BUFFER_LIST_INFO(net_buffer_list, TcpIpChecksumNetBufferListInfo);
  net_packet->lso_info.Value =
      NET_BUFFER_LIST_INFO(net_buffer_list, TcpLargeSendNetBufferListInfo);

  return net_packet;
}

// Build descriptor for TxPacket.
void TxRing::FillTxPacketDescriptor(const TxNetBuffer& tx_net_buffer,
                                    const PacketSegmentInfo& segment_info,
                                    TxPacketDescriptor* descriptor) {
  if (tx_net_buffer.is_lso()) {
    descriptor->type_flags = kTxDescriptorTypeTSO | kTxFlagChecksumOffload;
    // Gvnic requires both checksum offset and l4 offset in 2-byte unit.
    descriptor->checksum_offset =
        tx_net_buffer.GetChecksumOffsetWithinL4() >> 1;
    descriptor->l4_offset = tx_net_buffer.GetL4Offset() >> 1;
  } else if (tx_net_buffer.is_checksum_offload()) {
    descriptor->type_flags = kTxDescriptorTypeSTD | kTxFlagChecksumOffload;
    // Gvnic requires both checksum offset and l4 offset in 2-byte unit.
    descriptor->checksum_offset =
        tx_net_buffer.GetChecksumOffsetWithinL4() >> 1;
    descriptor->l4_offset = tx_net_buffer.GetL4Offset() >> 1;
  } else {
    descriptor->type_flags = kTxDescriptorTypeSTD;
    descriptor->checksum_offset = 0;
    descriptor->l4_offset = 0;
  }

  descriptor->descriptor_count = 1 + segment_info.data_segment_count;
  descriptor->packet_length =
      RtlUshortByteSwap((USHORT)tx_net_buffer.data_length());
  descriptor->segment_length =
      RtlUshortByteSwap((USHORT)segment_info.packet_length);
  descriptor->segment_address =
      RtlUlonglongByteSwap(segment_info.packet_offset);
}

// Build descriptor for TxSegment.
void TxRing::FillTxSegmentDescriptor(UINT64 offset, UINT32 length,
                                     const TxNetBuffer& tx_net_buffer,
                                     TxSegmentDescriptor* descriptor) {
  descriptor->type_flags = kTxDescriptorTypeSEG;
  descriptor->segment_length = RtlUshortByteSwap((USHORT)length);
  descriptor->segment_address = RtlUlonglongByteSwap(offset);

  if (tx_net_buffer.is_lso()) {
    if (tx_net_buffer.is_lso_ipv6()) {
      descriptor->type_flags |= kTxTsoIpV6;
    }
    descriptor->tso_mss = RtlUshortByteSwap(tx_net_buffer.max_segment_size());
    // L3 offset is in 2 byte unit.
    descriptor->l3_offset = tx_net_buffer.GetL3Offset() >> 1;
  }
}

void TxRing::CompleteNetBufferListWithStatus(NET_BUFFER_LIST* net_buffer_list,
                                             NDIS_STATUS status,
                                             bool is_dpc_level) {
  NET_BUFFER_LIST_STATUS(net_buffer_list) = status;
  NdisMSendNetBufferListsComplete(
      miniport_handle(), net_buffer_list,
      is_dpc_level ? NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL : 0);
}
