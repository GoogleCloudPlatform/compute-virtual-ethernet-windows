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

#ifndef RING_BASE_H_
#define RING_BASE_H_
#include <ndis.h>

#include "abi.h"                 // NOLINT: include directory
#include "adapter_resource.h"    // NOLINT: include directory
#include "adapter_statistics.h"  // NOLINT: include directory
#include "queue_page_list.h"     // NOLINT: include directory
#include "shared_memory.h"       // NOLINT: include directory

__declspec(align(kCacheLineSize)) class RingBase {
 public:
  RingBase()
      : is_init_(0),
        id_(0),
        slice_(0),
        traffic_class_(0),
        notify_id_(0),
        use_raw_addressing_(false),
        queue_page_list_(nullptr),
        is_prepare_for_release_(false) {}
  ~RingBase();

  // Return the ring id based on slice and traffic class number.
  // max_slices comes from device queue config.
  // It fills the traffic class first before move to next one, for example:
  // +------+---------+---------+---------+
  // |      | slice_0 | slice_1 | slice_2 |
  // +------+---------+---------+---------+
  // | tc_0 |       0 |       1 |       2 |
  // | tc_1 |       3 |       4 |       5 |
  // | tc_2 |       6 |       7 |       8 |
  // +------+---------+---------+---------+
  // This way, it aligns with notification block sequence.
  static UINT GetRingId(UINT max_slices, UINT slice, UINT traffic_class) {
    return max_slices * traffic_class + slice;
  }

  // Not copyable or movable
  RingBase(const RingBase&) = delete;
  RingBase& operator=(const RingBase&) = delete;

  // Initialize the object and allocate required resources.
  // Params:
  //    id: unique id of the ring
  //    slice: slice number of the ring.
  //    traffic_class: traffic_class for the ring.
  //    use_raw_addressing: whether to use raw physical address or offset from
  //      queue_page_list.
  //    queue_page_list: list of pages registered with the device. Net packets
  //      need to be copied into these pages for the device to send out. This
  //      will be nullptr for tx rings when use_raw_addressing is set.
  //    notify_id: the index of the ring in the NotificationBlock
  //    adapter_resource: pointer to the resource object, required for accessing
  //      doorbells and miniport handle.
  //    statistics: pointer to the adapter statistics object, used to tracking
  //      number of bytes, packets get sent/received.
  //    device_counters: event counter array registered with the device. For tx
  //      ring, device update it with the total number of packets sent. For rx
  //      ring, it is not currently used.
  //
  //  Return:
  //    true if allocation succeeds or false otherwise.
  bool Init(UINT32 id, UINT32 slice, UINT32 traffic_class,
            bool use_raw_addressing, QueuePageList* queue_page_list,
            UINT32 notify_id, AdapterResources* adapter_resource,
            AdapterStatistics* statistics,
            const DeviceCounter* device_counters);

  // Release queue resources.
  void Release();

  QueuePageList* queue_page_list() const { return queue_page_list_; }
  UINT32 id() const { return id_; }
  UINT32 slice() const { return slice_; }
  UINT32 traffic_class() const { return traffic_class_; }
  PHYSICAL_ADDRESS ResourcesPhysicalAddress() const {
    return resources_.physical_address();
  }

  UINT32 notify_id() const { return notify_id_; }

  // Whether the ring has been initialized.
  bool is_init() const { return !!is_init_; }

  bool use_raw_addressing() const { return use_raw_addressing_; }

  // This function calls PrepareForRelease, but synchronized with any DPC
  // interrupt on the same notify block. This prevents us from changing the
  // ring state during an interrupt.
  void SynchronousPrepareForRelease();

  // Called by SynchronousPrepareForRelease's interrupt synchronized callback.
  // This is invoked at dispatch level.
  void PrepareForRelease() { is_prepare_for_release_ = true; }

 protected:
  // Write value to ring doorbell.
  void WriteDoorbell(ULONG value);

  // Read the counter value from the device counter array.
  UINT32 ReadPacketsSent();

  NDIS_HANDLE miniport_handle() const {
    return adapter_resource_->miniport_handle();
  }

  NDIS_HANDLE net_buffer_list_pool() const {
    return adapter_resource_->net_buffer_list_pool();
  }

  NDIS_HANDLE dma_handle() const { return adapter_resource_->dma_handle(); }

  ULONG recommended_sg_list_size() const {
    return adapter_resource_->recommended_sg_list_size();
  }

  AdapterStatistics* statistics() { return adapter_statistics_; }

  // Atomically invalidates this ring, and returns TRUE if this ring was
  // initialized before invalidation. The thread calling Invalidate should
  // also call Release.
  bool Invalidate();

  bool IsPrepareForRelease() const { return is_prepare_for_release_; }

 private:
  // Doorbell index could be updated by device and need to read it refresh.
  UINT32 GetDoorbellIndex() const;

  // Counter index could be updated by device and need to read it refresh.
  UINT32 GetDeviceCounterIndex() const;

  // check whether the ring is initialized.
  LONG is_init_;

  UINT32 id_;
  UINT32 slice_;
  UINT32 traffic_class_;

  UINT32 notify_id_;

  AdapterResources* adapter_resource_;
  AdapterStatistics* adapter_statistics_;
  const DeviceCounter* device_counters_;

  SharedMemory<QueueResources> resources_;

  // Whether to use raw physical address or offset from the queue page list.
  bool use_raw_addressing_;
  QueuePageList* queue_page_list_;

  // Whether this ring is being readied to be released. Rx rings will stop
  // processing packets asynchronously, and Tx rings will stop accepting
  // traffic and begin to drain.
  bool is_prepare_for_release_;
};

#endif  // RING_BASE_H_
