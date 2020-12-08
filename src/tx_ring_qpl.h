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

#ifndef TX_RING_QPL_H_
#define TX_RING_QPL_H_

#include <ndis.h>

#include "abi.h"                 // NOLINT: include directory
#include "adapter_resource.h"    // NOLINT: include directory
#include "adapter_statistics.h"  // NOLINT: include directory
#include "device_fifo_queue.h"   // NOLINT: include directory
#include "device_parameters.h"   // NOLINT: include directory
#include "netutils.h"            // NOLINT: include directory
#include "queue_page_list.h"     // NOLINT: include directory
#include "tx_ring.h"             // NOLINT: include directory

__declspec(align(kCacheLineSize)) class TxRingQpl : public TxRing {
 public:
  TxRingQpl()
      : TxRing(),
        segment_allocated_size_(nullptr),
        current_net_buffer_to_send_(nullptr),
        current_net_buffer_list_to_send_(nullptr) {}
  ~TxRingQpl() override { Release(); };

  // Not copyable or movable
  TxRingQpl(const TxRingQpl&) = delete;
  TxRingQpl& operator=(const TxRingQpl&) = delete;

  // Initialize the object and allocate required resources.
  //  - id: the id of the tx ring.
  //  - slice: the assigned core.
  //  - traffic_class: the assigned traffic class / priority queue.
  //  - num_descriptor: number of packet/segment descriptors.
  //  - queue_page_list: assigned queue. This is where the net packets get
  //      copied into when use_raw_addressing is disabled.
  //  - notify_id: notification block id.
  //  - adapter_resource: used to ring door bell and read counters.
  //  - statistics: used to trace the sending packets.
  //  - device_counters: used to read packets sent by the devices.
  bool Init(UINT32 id, UINT32 slice, UINT32 traffic_class,
            UINT32 num_descriptor, QueuePageList* queue_page_list,
            UINT32 notify_id, AdapterResources* adapter_resource,
            AdapterStatistics* statistics,
            const DeviceCounter* device_counters);

  // Release descriptor_ring_, resources_
  // Safe to call even if Init is not invoked.
  void Release() override;

  // Send all NET_BUFFER from given NET_BUFFER_LIST. Can be called at dispatch
  // or passive level.
  void SendBufferList(PNET_BUFFER_LIST net_buffer_list,
                      bool is_dpc_level) override;

  // Wrapper around ProcessCompletePacketsWithoutCompletingNbls. This will
  // also complete any net buffer lists scheduled during this callback.
  void ProcessCompletePackets() override;

  // This callback is not used by QPL TxRings.
  void ProcessSGList(NET_BUFFER* net_buffer,
                     SCATTER_GATHER_LIST* scatter_gather_list) override {
    UNREFERENCED_PARAMETER(net_buffer);
    UNREFERENCED_PARAMETER(scatter_gather_list);

    NT_ASSERT(false);
  }

 private:
  // Free all memories allocated by the packet_to_send_ and packet_to_complete_
  // list. This should be called when the adapter is removed or reset.
  void CleanPendingPackets();

  // Send packets from packet_to_send_. Ring doorbell once. Completed net buffer
  // lists are prepended to nbl_completion_list. lock_ must be held when calling
  // this function.
  _Requires_lock_held_(lock_) NDIS_STATUS
      SendNetPackets(PNET_BUFFER_LIST* nbl_completion_list);

  // Find the next net_buffer from the head of packet_to_send_. Once a NBL is
  // completed, it is prepended to nbl_completion_list. Returns nullptr if the
  // list is empty.
  NET_BUFFER* GetNextNetBufferToSend(PNET_BUFFER_LIST* nbl_completion_list);

  // Frees descriptors and QPL resources once the NIC has finished with packets
  // and then attempts to schedule pending NBLs using the now available
  // resources. This does not complete the actual net buffer lists, but adds
  // them to nbl_completion_list to be completed by the caller.
  void ProcessCompletePacketsWithoutCompletingNbls(
      PNET_BUFFER_LIST* nbl_completion_list);

  // Array to store the allocated size of each tx segment.
  // Size: num_descriptor_.
  UINT32* segment_allocated_size_;

  NET_BUFFER* current_net_buffer_to_send_;
  TxNetBufferList* current_net_buffer_list_to_send_;

  _Guarded_by_(lock_) LIST_ENTRY packet_to_send_;

  DeviceFifoQueue device_queue_;
};

#endif  // TX_RING_QPL_H_
