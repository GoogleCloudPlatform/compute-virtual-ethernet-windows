/*
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef PACKET_ASSEMBLER_H_
#define PACKET_ASSEMBLER_H_

#include <ndis.h>

#include "adapter_statistics.h"  // NOLINT: include directory
#include "offload.h"             // NOLINT: include directory
#include "rx_packet.h"           // NOLINT: include directory

// Collection class for build NetBufferList and track total count of
// NET_BUFFER_LISTs.
class NetBufferListContainer final {
  // Struct represent single coalesced unit(SCU).
  struct CoalescedUnit {
    // Check whether the object is a valid candidate for coalescing.
    bool is_valid;
    USHORT count;
    // The last mdl in the NET_BUFFER MDL list. New payload gets attached to
    // this mdl.
    MDL* current_mdl;
    NET_BUFFER* net_buffer;
    // Total length of current merged packet.
    UINT packet_length;
    // The expected next seq num.
    UINT32 next_seq_num;
    IPv4Header* ipv4_header;
    TcpHeader* tcp_header;
  };

 public:
  NetBufferListContainer()
      : head_(nullptr), tail_(nullptr), count_(0), coalesced_unit_({}) {}

  NetBufferListContainer(const NetBufferListContainer&) = delete;
  NetBufferListContainer& operator=(const NetBufferListContainer&) = delete;

  // Add net_buffer_list to NetBufferListContainer and increase the count.
  void AddNetBufferList(NET_BUFFER_LIST* net_buffer_list,
                        const RxPacket& rx_packet,
                        bool is_coalescing_candidate);

  // Returns the number of NET_BUFFER_LISTs that have been added.
  UINT count() const { return count_; }
  NET_BUFFER_LIST* head() { return head_; }
  NET_BUFFER_LIST* tail() { return tail_; }

#ifdef SUPPORT_RSC
  bool HasValidCoalescedUnit() const { return coalesced_unit_.is_valid; }

  IPv4Header* coalesced_unit_ipv4_header() const {
    NT_ASSERT(HasValidCoalescedUnit());
    return coalesced_unit_.ipv4_header;
  }

  TcpHeader* coalesced_unit_tcp_header() const {
    NT_ASSERT(HasValidCoalescedUnit());
    return coalesced_unit_.tcp_header;
  }

  UINT32 coalesced_unit_next_seq_num() const {
    NT_ASSERT(HasValidCoalescedUnit());
    return coalesced_unit_.next_seq_num;
  }

  UINT coalesced_unit_packet_length() const {
    NT_ASSERT(HasValidCoalescedUnit());
    return coalesced_unit_.packet_length;
  }

  void ExtendCoalecedUnit(MDL* mdl, UINT data_payload_length,
                          const TcpHeader& tcp_header);
#endif  // SUPPORT_RSC

 private:
  void ClearCoalescedUnit();

  NET_BUFFER_LIST* head_;
  NET_BUFFER_LIST* tail_;
  UINT count_;
  CoalescedUnit coalesced_unit_;
};

// PacketAssembler accept incoming packets and try to run Receive Segment
// Coalescing (RSC) logic among packet to coalesce multiple TCP segments and
// indicate them as a single packet to the kernel.
//
// One PacketAssembler should be constructed per slice and shared among all
// rx rings in the same slice.
//
// NOTE: object is not thread safe.
class PacketAssembler final {
 public:
  explicit PacketAssembler(UINT max_nbls_to_indicate,
                           NDIS_HANDLE net_buffer_list_pool,
                           NDIS_HANDLE miniport_handle, bool coalescing_enabled,
                           AdapterStatistics* statistics)
      : num_nbls_(0),
        max_nbls_to_indicate_(max_nbls_to_indicate),
        segment_coalescing_enabled_(coalescing_enabled),
        net_buffer_list_pool_(net_buffer_list_pool),
        miniport_handle_(miniport_handle),
        statistics_(statistics) {}

  // Add packet to a list where it will get reported as a NetBufferList which
  // accepts a callback when the up layer processing is finished.
  // Return null if it reaches max NBL or run out of resources.
  NET_BUFFER_LIST* ProcessAsyncPacket(RxPacket* rx_packet);

  // Add packet to a list where it will get reported as a NetBufferList which
  // regains the ownership immediately after ReportPackets is returned.
  // Return null if it reaches max NBL or run out of resources.
  NET_BUFFER_LIST* ProcessSyncPacket(RxPacket* rx_packet);

  // Report all pending NetBufferList through
  // NdisMIndicateReceiveNetBufferLists.
  void ReportPackets(NDIS_HANDLE miniport_handle);

  PacketAssembler(const PacketAssembler&) = delete;
  PacketAssembler& operator=(const PacketAssembler&) = delete;

  bool CanAllocateNBL();

 private:
  NET_BUFFER_LIST* ProcessPacket(RxPacket* rx_packet,
                                 NetBufferListContainer* nbl_container);

  void ReportReceiveNetBufferList(NDIS_HANDLE miniport_handle,
                                  NET_BUFFER_LIST* net_buffer_list,
                                  UINT32 num_net_buffer_list,
                                  ULONG receive_flag);

  NET_BUFFER_LIST* AllocateNewNBL(RxPacket* new_rx_packet,
                                  NetBufferListContainer* nbl_container,
                                  bool is_coalescing_candidate);

#ifdef SUPPORT_RSC
  void MergePackets(const RxPacket& new_rx_packet,
                    NetBufferListContainer* nbl_container);
#endif  // SUPPORT_RSC

  NetBufferListContainer async_net_buffer_list_;
  NetBufferListContainer sync_net_buffer_list_;
  UINT max_nbls_to_indicate_;
  UINT num_nbls_;

  NDIS_HANDLE const net_buffer_list_pool_;
  NDIS_HANDLE const miniport_handle_;
  AdapterStatistics* const statistics_;

  bool segment_coalescing_enabled_;
};

#endif  // PACKET_ASSEMBLER_H_
