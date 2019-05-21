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

#ifndef TX_RING_H_
#define TX_RING_H_

#include <ndis.h>

#include "abi.h"                 // NOLINT: include directory
#include "adapter_resource.h"    // NOLINT: include directory
#include "adapter_statistics.h"  // NOLINT: include directory
#include "admin_queue.h"         // NOLINT: include directory
#include "device_fifo_queue.h"   // NOLINT: include directory
#include "device_parameters.h"   // NOLINT: include directory
#include "netutils.h"            // NOLINT: include directory
#include "queue_page_list.h"     // NOLINT: include directory
#include "ring_base.h"           // NOLINT: include directory

__declspec(align(kCacheLineSize)) class TxRing final : public RingBase {
 public:
  TxRing()
      : RingBase(),
        num_descriptor_(0),
        current_net_buffer_to_send_(nullptr),
        current_net_buffer_list_to_send_(nullptr) {}
  ~TxRing();

  // Not copyable or movable
  TxRing(const TxRing&) = delete;
  TxRing& operator=(const TxRing&) = delete;

  // Initialize the object and allocate required resources.
  //  - id: the id of the tx ring.
  //  - slice: the assigned core.
  //  - traffic_class: the assigned traffic class / priority queue.
  //  - descriptor_count: number of packet/segment descriptors.
  //  - queue_page_list: assigned queue. This is where the net packets get
  //      copied into.
  //  - notify_id: notification block id.
  //  - adapter_resource: used to ring door bell and read counters.
  //  - statistics: used to trace the sending packets.
  //  - device_counters: used to read packets sent by the devices.
  bool Init(UINT32 id, UINT32 slice, UINT32 traffic_class,
            UINT32 descriptor_count, QueuePageList* queue_page_list,
            UINT32 notify_id, AdapterResources* adapter_resource,
            AdapterStatistics* statistics,
            const DeviceCounter* device_counters);

  // Release descriptor_ring_, resources_
  // Safe to call even if Init is not invoked.
  void Release();

  // Send all NET_BUFFER from given NET_BUFFER_LIST.
  // is_dpc_level - whether it is running in dispatch level IRQL.
  void SendBufferList(PNET_BUFFER_LIST net_buffer_list, bool is_dpc_level);

  PHYSICAL_ADDRESS descriptor_ring_physical_address() const {
    return descriptor_ring_.physical_address();
  }

  // Read the counter for the ring and go through packet_to_complete_ list to
  // report send completion.
  void ProcessCompletePackets();

  void SetPacketHeaderLength(const EthHeaderLength& eth_header_length) {
    eth_header_len_ = eth_header_length;
  }

 private:
  // Send packets from packet_to_send_. Ring doorbell once.
  // packet_list_spin_lock_ must be held.
  _Requires_lock_held_(packet_list_spin_lock_) void SendNetPackets();

  void CompleteNetBufferListWithStatus(NET_BUFFER_LIST* net_buffer_list,
                                       NDIS_STATUS status, bool is_dpc_level);

  // Free all memories allocated by the packet_to_send_ and packet_to_complete_
  // list.
  // This should be called when the adapter is removed or reset.
  void CleanPendingPackets();

  // Return how many descriptors are still available.
  UINT GetAvailableDescriptors() const {
    return num_descriptor_ - num_request_segments_ + num_sent_segments_;
  }

  // Find the next net_buffer from the head of packet_to_send_.
  // Return nullptr if the list is empty.
  NET_BUFFER* GetNextNetBufferToSend();

  UINT num_descriptor_;
  // Size: num_descriptor_.
  SharedMemory<TxDescriptor> descriptor_ring_;

  // Array to store the allocated size of each tx segment.
  // Size: num_descriptor_.
  UINT32* segment_allocated_size_;

  // Unsigned is required to correctly handle the overflow scenario.
  // Number of segments that driver request the device to send.
  UINT num_request_segments_;
  // Number of segments that device has sent out.
  UINT num_sent_segments_;

  // Used to do mask over num_request_segments_ to get in range descriptor
  // index.
  UINT descriptor_mask_;

  NET_BUFFER* current_net_buffer_to_send_;
  TxNetBufferList* current_net_buffer_list_to_send_;

  LIST_ENTRY packet_to_send_;
  NDIS_SPIN_LOCK packet_list_spin_lock_;

  DeviceFifoQueue device_queue_;

  EthHeaderLength eth_header_len_;
};

#endif  // TX_RING_H_
