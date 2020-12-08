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
#include "device_fifo_queue.h"   // NOLINT: include directory
#include "device_parameters.h"   // NOLINT: include directory
#include "netutils.h"            // NOLINT: include directory
#include "queue_page_list.h"     // NOLINT: include directory
#include "ring_base.h"           // NOLINT: include directory
#include "utils.h"               // NOLINT: include directory

__declspec(align(kCacheLineSize)) class TxRing : public RingBase {
 public:
  TxRing()
      : RingBase(),
        num_descriptor_(0),
        num_request_segments_(0),
        num_sent_segments_(0),
        descriptor_mask_(0) {}
  virtual ~TxRing() {}

  // Not copyable or movable
  TxRing(const TxRing&) = delete;
  TxRing& operator=(const TxRing&) = delete;

  // New must be used instead of AllocateMemory so that the vtable can be
  // initialized. This also calls the constructor.
  void* operator new(size_t Size, NDIS_HANDLE MiniportHandle) noexcept {
    PVOID memory = NdisAllocateMemoryWithTagPriority(
      MiniportHandle, (UINT)Size, kGvnicMemoryTag, NormalPoolPriority);
    if (memory != nullptr) {
      NdisZeroMemory(memory, Size);
    }

    return memory;
  }

  // The driver should call Release and then FreeMemory instead of using Delete.
  void operator delete(PVOID Address, size_t Count) noexcept {
    UNREFERENCED_PARAMETER(Count);
    NdisFreeMemory(Address, /*Length=*/0, /*MemoryFlags=*/0);
  }

  // Release descriptor_ring_, resources_
  // Safe to call even if Init is not invoked.
  virtual void Release();

  // Send all NET_BUFFER from given NET_BUFFER_LIST.
  // is_dpc_level - whether it is running in dispatch level IRQL.
  virtual void SendBufferList(PNET_BUFFER_LIST net_buffer_list,
                              bool is_dpc_level) = 0;

  // Called via an interrupt when the device completes past some number of
  // descriptors. Always called at dispatch level.
  virtual void ProcessCompletePackets() = 0;

  // Callback used by direct memory access TxRings.
  virtual void ProcessSGList(NET_BUFFER* net_buffer,
                             SCATTER_GATHER_LIST* scatter_gather_list) = 0;

  PHYSICAL_ADDRESS descriptor_ring_physical_address() const {
    return descriptor_ring_.physical_address();
  }

  void SetPacketHeaderLength(const EthHeaderLength& eth_header_length) {
    eth_header_len_ = eth_header_length;
  }

  bool IsAcceptingTraffic() const { return !IsPrepareForRelease(); }

 protected:
  // Initialize the object and allocate required resources.
  //  - id: the id of the tx ring.
  //  - slice: the assigned core.
  //  - traffic_class: the assigned traffic class / priority queue.
  //  - num_descriptor: number of packet/segment descriptors.
  //  - use_raw_addressing: whether to use raw physical address or offset
  //      from queue_page_list.
  //  - queue_page_list: assigned queue. This is where the net packets get
  //      copied into when use_raw_addressing is disabled.
  //  - notify_id: notification block id.
  //  - adapter_resource: used to ring door bell and read counters.
  //  - statistics: used to trace the sending packets.
  //  - device_counters: used to read packets sent by the devices.
  bool Init(UINT32 id, UINT32 slice, UINT32 traffic_class,
            UINT32 num_descriptor, bool use_raw_addressing,
            QueuePageList* queue_page_list, UINT32 notify_id,
            AdapterResources* adapter_resource, AdapterStatistics* statistics,
            const DeviceCounter* device_counters);

  TxNetBufferList* GetTxNetBufferList(PNET_BUFFER_LIST net_buffer_list);

  void CompleteNetBufferListWithStatus(NET_BUFFER_LIST* net_buffer_list,
                                       NDIS_STATUS status, bool is_dpc_level);

  void FillTxPacketDescriptor(const TxNetBuffer& tx_net_buffer,
                              const PacketSegmentInfo& segment_info,
                              TxPacketDescriptor* descriptor);

  void FillTxSegmentDescriptor(UINT64 offset, UINT32 length,
                               const TxNetBuffer& tx_net_buffer,
                               TxSegmentDescriptor* descriptor);

  // Return how many descriptors are still available.
  UINT GetAvailableDescriptors() const {
    return num_descriptor_ - num_request_segments_ + num_sent_segments_;
  }

  // Number of descriptor entries. Must be a power of 2.
  UINT num_descriptor_;

  // Size: num_descriptor_.
  SharedMemory<TxDescriptor> descriptor_ring_;

  // Unsigned is required to correctly handle the overflow scenario.
  // Number of segments that driver request the device to send.
  _Guarded_by_(lock_) UINT num_request_segments_;

  // Number of segments that device has sent out.
  UINT num_sent_segments_;

  // Used to do mask over num_request_segments_ to get in range descriptor
  // index.
  UINT descriptor_mask_;

  EthHeaderLength eth_header_len_;

  NDIS_SPIN_LOCK lock_;
};

#endif  // TX_RING_H_
