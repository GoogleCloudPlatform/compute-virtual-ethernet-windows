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

#ifndef TX_RING_DMA_H_
#define TX_RING_DMA_H_

#include <ndis.h>

#include "abi.h"                 // NOLINT: include directory
#include "adapter_resource.h"    // NOLINT: include directory
#include "adapter_statistics.h"  // NOLINT: include directory
#include "device_parameters.h"   // NOLINT: include directory
#include "netutils.h"            // NOLINT: include directory
#include "tx_ring.h"             // NOLINT: include directory

// We choose the number of scatter gather lists to preallocate based on the
// number of descriptors divided by a factor to account for SG lists containing
// multiple fragments.
constexpr UINT32 kPreallocatedSGListFactor = 8;

struct PreallocatedSGList {
  SLIST_ENTRY list_entry;
  UINT32 buffer_size;
  PVOID buffer;
};

struct SharedMemoryBuffer {
  SLIST_ENTRY list_entry;
  UINT32 buffer_size;
  SharedMemory<UCHAR> shared_memory;
};

struct PendingNetBuffer {
  LIST_ENTRY list_entry;
  NET_BUFFER* net_buffer;
};

__declspec(align(kCacheLineSize)) class TxBufferPool {
 public:
  TxBufferPool() : is_init_(0) {}
  ~TxBufferPool() { Release(); }

  // Not copyable or movable
  TxBufferPool(const TxBufferPool&) = delete;
  TxBufferPool& operator=(const TxBufferPool&) = delete;

  bool InitializeTxBufferPool(NDIS_HANDLE miniport_handle,
                              UINT32 num_descriptors);

  void Release();

  // Gets a buffer from the pool which is at least size min_buffer_size. If
  // there's no available buffer large enough this returns nullptr.
  SharedMemoryBuffer* GetBufferFromPool(UINT32 min_buffer_size);

  // Returns a buffer to the correct pool depending on its size.
  void ReturnBufferToPool(SharedMemoryBuffer* buffer_entry);

 private:
  // Frees optional shared memory buffers. This may cause many packets to fail
  // with NDIS_STATUS_RESOURCES.
  void EnableLowMemoryMode();

  bool Invalidate() { return !!InterlockedExchange(&is_init_, 0); }
  bool IsInitialized() const { return !!is_init_; }

  // Releases all allocated buffers and frees the spinlock.
  void FreeTxBufferPool();

  // Frees the buffers in a specified pool.
  void FreeBufferPool(SLIST_HEADER* pool);

  // Allocates shared memory buffers and inserts them into the provided
  // interlocked list. Returns false if any allocation failed.
  bool AllocateBuffers(NDIS_HANDLE miniport_handle, UINT32 count, UINT32 size,
                       SLIST_HEADER* pool);

  LONG is_init_;

  SLIST_HEADER small_buffers_;
  SLIST_HEADER medium_buffers_;
  SLIST_HEADER large_buffers_;
  SLIST_HEADER enormous_buffers_;
  NDIS_SPIN_LOCK buffer_pool_spin_lock_;
};

__declspec(align(kCacheLineSize)) class TxRingDma : public TxRing {
 public:
  TxRingDma()
      : TxRing(),
        net_buffers_(nullptr),
        consolidated_descriptor_buffers_(nullptr) {}
  ~TxRingDma() override { Release(); }

  // Not copyable or movable
  TxRingDma(const TxRingDma&) = delete;
  TxRingDma& operator=(const TxRingDma&) = delete;

  // Initialize the object and allocate required resources.
  //  - id: the id of the tx ring.
  //  - slice: the assigned core.
  //  - traffic_class: the assigned traffic class / priority queue.
  //  - num_descriptor: number of packet/segment descriptors.
  //  - notify_id: notification block id.
  //  - adapter_resource: used to ring door bell and read counters.
  //  - statistics: used to trace the sending packets.
  //  - device_counters: used to read packets sent by the devices.
  bool Init(UINT32 id, UINT32 slice, UINT32 traffic_class,
            UINT32 num_descriptor, UINT32 notify_id,
            AdapterResources* adapter_resource, AdapterStatistics* statistics,
            const DeviceCounter* device_counters);

  // Release descriptor_ring_, resources_
  // Safe to call even if Init is not invoked.
  void Release() override;

  // Splits a list of NET_BUFFER_LISTs into individual NET_BUFFER_LISTs before
  // processing them.
  void SendBufferList(PNET_BUFFER_LIST net_buffer_list,
                      bool is_dpc_level) override;

  // Send all NET_BUFFER from given NET_BUFFER_LIST.
  void ProcessNetBufferList(PNET_BUFFER_LIST net_buffer_list,
                            bool is_dpc_level);

  // Read the counter for the ring and go through packet_to_complete_ list to
  // report send completion.
  void ProcessCompletePackets() override;

  // Process the SCATTER_GATHER_LIST from the callback for
  // NdisMAllocateNetBufferSGList. Must be called at DISPATCH_LEVEL.
  void ProcessSGList(NET_BUFFER* net_buffer,
                     SCATTER_GATHER_LIST* scatter_gather_list) override;

 private:
  // Report pending net buffers as failed. Called when the adapter is removed
  // or reset.
  void CleanPendingPackets();

  // Increase num_sent_net_buffer in tx_net_buffer_list and report
  // complete state if all net_bufffers are sent.
  void ReportNetBufferSent(TxNetBufferList* tx_net_buffer_list,
                           bool is_dpc_level);

  NDIS_STATUS AttemptProcessSGList(NET_BUFFER* net_buffer,
                                   SCATTER_GATHER_LIST* scatter_gather_list);

  // Returns the index of the next scatter gather element past the provided
  // offset, and sets offset_into_current_element. If the index is equal to the
  // number of elements, there is no data left in the scatter gather list.
  UINT32 GetNextSGIndexPastOffset(
      const SCATTER_GATHER_LIST& scatter_gather_list, UINT32 current_index,
      UINT32 offset, UINT32* offset_into_current_element);

  // Helper function to create and write segment descriptors from a scatter
  // gather list.
  void WriteSegmentDescriptorsFromSGList(
      const SCATTER_GATHER_LIST& scatter_gather_list, UINT32 index_from,
      UINT32 index_to, UINT32 first_segment_offset,
      const TxNetBuffer& tx_net_buffer, TxPacketDescriptor* packet_desc,
      UINT32* pending_num_request_segments);

  // Helper function to write an individual segment.
  void WriteSegmentDescriptor(UINT32 length, UINT64 address,
                              const TxNetBuffer& tx_net_buffer,
                              TxPacketDescriptor* packet_desc,
                              UINT32* pending_num_request_segments);

  // Marks the net buffer as failed, frees the scatter gather list if it
  // was allocated, and returns resources. Calling this might invalidate the
  // NET_BUFFER_LIST if this was the final NET_BUFFER.
  void FailProcessSGList(NET_BUFFER* net_buffer, bool is_dpc_level,
                         NDIS_STATUS error_status);

  // Marks a tx net buffer list as failed, and increments the net buffer ready
  // counter. If this is called for the final net buffer in the list, this
  // will trigger a finalization of the entire chain.
  void FailTxNetBufferList(TxNetBufferList* tx_nbl, bool is_dpc_level,
                           NDIS_STATUS error_status);

  // Reports a NBL as completed, and prepends it to the completion chain.
  void ReportNetBufferSentWithoutCompletion(TxNetBufferList* tx_net_buffer_list,
                                            PNET_BUFFER_LIST* nbl);

  // Returns all in-use buffers to the buffer pool, and deallocates the pool.
  void FreeBufferPool();

  // Helper function to return a buffer if one was used.
  void ReturnBufferToPool(UINT32 desc);

  // Pops net buffers off of the net_buffer_to_send_queue_ queue and tries
  // to write them to the descriptor ring. This stops at the first net buffer
  // it fails to schedule.
  void SchedulePendingNetBuffers();

  // Helper function which inserts the provided net buffer, and all following
  // net buffers in the list into the work queue.
  void PendRemainingNetBuffers(NET_BUFFER* net_buffer);

  // Allocating and deallocating the preallocated SG lists is not thread safe.
  // The buffer size in each list entry is controlled by the adapter resources.
  // Requires that preallocated_sg_lists_lock_ is not held.
  bool PreallocateSGLists(UINT32 num_lists);
  void FreePreallocatedSGLists();

  // Gets a preallocated SG list from the pool, and returns nullptr if the pool
  // is empty. Requires that preallocated_sg_lists_lock_ is not held.
  PreallocatedSGList* GetPrellocatedSGListFromPool();

  // Returns the preallocated SG list to the pool, if one was allocated.
  // Requires that preallocated_sg_lists_lock_ is not held.
  void ReturnPreallocatedSGListToPool(NET_BUFFER* net_buffer);

  // Appends a net buffer to the end of a work queue. Requires that the
  // provided work_queue_lock is not held.
  bool AppendNetBufferToWorkQueue(NET_BUFFER* net_buffer,
                                  PLIST_ENTRY work_queue,
                                  PNDIS_SPIN_LOCK work_queue_lock);

  // Pushes a net buffer to the beginning of a work queue. This will be the
  // next net buffer serviced. Requires that the provided work_queue_lock is
  // not held.
  bool PrependNetBufferToWorkQueue(NET_BUFFER* net_buffer,
                                   PLIST_ENTRY work_queue,
                                   PNDIS_SPIN_LOCK work_queue_lock);

  // Pops a net buffer off the head of a work queue. Returns nullptr
  // if there's no net buffer to complete, and requires that the provided
  // work_queue_lock is not held.
  NET_BUFFER* PopNetBufferFromWorkQueue(PLIST_ENTRY work_queue,
                                        PNDIS_SPIN_LOCK work_queue_lock);

  // Contains preallocated shared memory buffers used to consolidate
  // descriptors. The number of buffers of each size is a related to the
  // size of the descriptor ring.
  TxBufferPool buffer_pool_;

  // Size: num_descriptor_.
  NET_BUFFER** net_buffers_;
  SharedMemoryBuffer** consolidated_descriptor_buffers_;

  SLIST_HEADER preallocated_sg_lists_;
  NDIS_SPIN_LOCK preallocated_sg_lists_lock_;

  LIST_ENTRY net_buffer_completion_queue_;
  NDIS_SPIN_LOCK net_buffer_completion_queue_lock_;

  LIST_ENTRY net_buffer_to_send_queue_;
  NDIS_SPIN_LOCK net_buffer_to_send_queue_lock_;

  NPAGED_LOOKASIDE_LIST net_buffer_work_queue_lookaside_list_;
};

#endif  // TX_RING_DMA_H_
