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

#ifndef RX_RING_H_
#define RX_RING_H_

#include "abi.h"                 // NOLINT: include directory
#include "adapter_resource.h"    // NOLINT: include directory
#include "adapter_statistics.h"  // NOLINT: include directory
#include "device_parameters.h"   // NOLINT: include directory
#include "packet_assembler.h"    // NOLINT: include directory
#include "queue_page_list.h"     // NOLINT: include directory
#include "ring_base.h"           // NOLINT: include directory
#include "rss_configuration.h"   // NOLINT: include directory
#include "rx_ring_entry.h"       // NOLINT: include directory
#include "shared_memory.h"       // NOLINT: include directory
#include "utils.h"               // NOLINT: include directory

// Default number of NBLs to indicate per DPC. Same as NDIS_INDICATE_ALL_NBLS
// but to support NDIS version other than NIDS620, define by ourselves.
constexpr UINT32 kIndicateAllNBLs = ~0ul;

__declspec(align(kCacheLineSize)) class RxRing final : public RingBase {
 public:
  RxRing()
      : RingBase(),
        num_descriptor_(0),
        rx_ring_entries_(nullptr),
        rss_enabled_(false),
        rss_hash_type_(0),
        rss_hash_function_(0),
        checksum_offload_enabled_(false) {}
  ~RxRing();

  // Not copyable or movable
  RxRing(const RxRing&) = delete;
  RxRing& operator=(const RxRing&) = delete;

  // Initialize the object and allocate required resources
  // Return true if allocation succeeds or false otherwise.
  bool Init(UINT32 id, UINT32 slice, UINT32 traffic_class,
            UINT32 num_descriptor, QueuePageList* queue_page_list,
            UINT32 notify_id, AdapterResources* adapter_resourcee,
            AdapterStatistics* statistics,
            const DeviceCounter* device_counters);

  void Release();

  PHYSICAL_ADDRESS DescriptorRingPhysicalAddr() const {
    return descriptor_ring_.physical_address();
  }

  PHYSICAL_ADDRESS DataRingPhysicalAddr() const {
    return data_ring_.physical_address();
  }

  // Tell the device the init free slots.
  void SetInitFreeSlot();

  // Process received packets, create NET_BUFFER_LIST and report it to OS.
  // Params:
  //  - [in]is_dpc_level: whether it is running in dpc level.
  //  - [in]max_nbls_to_indicate: specify how many nbls the method can indicate.
  //  - [out]remaining_nbls_to_indicate: remaining nbls the other ring can still
  //  indicate.
  // Return:
  //  true if all pending packets have been processed and false otherwise.
  bool ProcessPendingPackets(bool is_dpc_level,
                             PacketAssembler* packet_assembler);

  void set_checksum_offload(bool enabled) {
    checksum_offload_enabled_ = enabled;
  }

  // Save hash_type, hash_function from rss_config.
  void UpdateRssConfig(const RSSConfiguration& rss_config);

 private:
  bool InitRxEntries(NDIS_HANDLE pool_handle, NDIS_HANDLE miniport_handle);

  UINT32 num_descriptor_;
  // used to get correct descriptor index.
  UINT descriptor_mask_;

  // Next seq number of the packet rx is expected to match.
  UINT32 packet_seq_number_;
  // Counter for how many packets driver has processed.
  UINT32 packet_counter_;
  // Spin lock for packet_seq_number_ and packet_counter_.
  NDIS_SPIN_LOCK seq_counter_spin_lock_;

  RxRingEntry* rx_ring_entries_;

  SharedMemory<RxDataRingSlot> data_ring_;
  SharedMemory<RxDescriptor> descriptor_ring_;

  bool checksum_offload_enabled_;

  // RSS settings.
  bool rss_enabled_;
  UINT32 rss_hash_type_;
  UINT8 rss_hash_function_;

#ifdef DBG
  const UINT8* rss_secret_key_;
#endif
};

// Increase the pending count on RxRingEntry and save the pointer to
// NET_BUFFER_LIST.
inline void IncreaseRxDataRingPendingCount(RxRingEntry* rx_ring_entry,
                                           NET_BUFFER_LIST* net_buffer_list) {
  InterlockedIncrement16(&rx_ring_entry->pending_count);
  auto current_rx_ring_entry = reinterpret_cast<RxRingEntry*>(
      net_buffer_list->MiniportReserved[kNetBufferListRxRingEntryPtrIdx]);

  if (current_rx_ring_entry == nullptr) {
    net_buffer_list->MiniportReserved[kNetBufferListRxRingEntryPtrIdx] =
        rx_ring_entry;
  } else {
    if (current_rx_ring_entry->rsc_last == nullptr) {
      current_rx_ring_entry->rsc_next = rx_ring_entry;
      current_rx_ring_entry->rsc_last = rx_ring_entry;
    } else {
      current_rx_ring_entry->rsc_last->rsc_next = rx_ring_entry;
      current_rx_ring_entry->rsc_last = rx_ring_entry;
    }
  }
}

// Called on inside MiniportReturnNetBufferLists to decrease the pending count
// on associated rx data ring entry.
inline void DecreaseRxDataRingPendingCount(NET_BUFFER_LIST* net_buffer_list) {
  auto rx_ring_entry = reinterpret_cast<RxRingEntry*>(
      net_buffer_list->MiniportReserved[kNetBufferListRxRingEntryPtrIdx]);
  net_buffer_list->MiniportReserved[kNetBufferListRxRingEntryPtrIdx] = nullptr;

  while (rx_ring_entry != nullptr) {
    RxRingEntry* next_entry = rx_ring_entry->rsc_next;
    InterlockedDecrement16(&rx_ring_entry->pending_count);
    rx_ring_entry->rsc_last = nullptr;
    rx_ring_entry->rsc_next = nullptr;
    rx_ring_entry = next_entry;
  }
}

#endif  // RX_RING_H_
