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

#ifndef NOTIFY_MANAGER_H_
#define NOTIFY_MANAGER_H_

#include <ndis.h>

#include "abi.h"                // NOLINT: include directory
#include "device_parameters.h"  // NOLINT: include directory
#include "rx_ring.h"            // NOLINT: include directory
#include "shared_memory.h"      // NOLINT: include directory
#include "tx_ring.h"            // NOLINT: include directory

// Wrapper class for manipulating NotifyBlock struct.
//
// Caller can register rx or tx rings with the manager and it will assigned
// a notify_id which could be passed to the device.
// Later, the same notify_id can be used to look up corresponding tx or rx
// rings.
//
// To do unregister, call Reset() which erase all pointers to tx/rx rings and
// reset the internal counter.
//
// The class keeps pointer to rx_config, tx_config, rx_ring, tx_ring and those
// object MUST outlive NotifyManager object.
//
// Currently, each NotifyBlock can hold one tx ring and multiple rx rings
// since rx ring from different rx_group will share same interrupt.
class NotifyManager final {
 public:
  NotifyManager()
      : num_notify_blocks_(0),
        mgmt_msix_index_(0),
        msi_table_(nullptr),
        miniport_handle_(nullptr),
        rx_config_(nullptr),
        tx_config_(nullptr),
        notify_blocks_physical_address_(0),
        notify_blocks_(nullptr),
        message_id_to_notify_id_map_(nullptr) {}
  ~NotifyManager();

  // Initialize Object. Based on num_msi_vectors and policy on assigning
  // interrupt to rx/tx ring, it will adjust num_tx_slices and num_rx_slices
  // if necessary.
  // Return true if succeed and false otherwise.
  bool Init(NDIS_HANDLE miniport_handle,
            const IO_INTERRUPT_MESSAGE_INFO* msi_table, QueueConfig* tx_config,
            QueueConfig* rx_config);
  void Release();

  // Register Rx Ring and return the notify id.
  UINT32 RegisterRxRing(UINT32 slice_num, RxRing* rx_ring);
  // Register Tx Ring and return the notify id.
  UINT32 RegisterTxRing(UINT32 slice_num, TxRing* tx_ring);

  // Clean up all registered tx/rx rings.
  void Reset();

  // Get num of rx rings for specific notify block.
  UINT32 GetRxRingCount(UINT32 message_id) const;
  // Get rx ring from specific notify block. Since one notify block can contains
  // multiple rx rings, method also requires ring_idx.
  RxRing* GetRxRing(UINT32 message_id, UINT32 ring_idx) const;

  // Get trx ring from notify block.
  TxRing* GetTxRing(UINT32 message_id) const;

  UINT64 notify_blocks_physical_address() const {
    return notify_blocks_physical_address_;
  }

  // Get notify block msi vector base number.
  UINT32 notify_block_msi_base_index() const;

  // Get manager queue msi number.
  UINT32 manager_queue_message_id() const { return mgmt_msix_index_; }

  UINT32 num_notify_blocks() const { return num_notify_blocks_; }

  // Got doorbell index for notify block.
  UINT32 GetInterruptDoorbellIndex(UINT32 message_id) const;

  // Updates the processor affinities for rx slices if required by the RSS
  // configuration's indirection table.
  void UpdateRxProcessorAffinities(const RSSConfiguration& rss_config);

  NotifyManager(const NotifyManager&) = delete;
  NotifyManager& operator=(const NotifyManager&) = delete;

 private:
  UINT32 GetTxNotifyId(UINT32 slice_num);
  UINT32 GetRxNotifyId(UINT32 slice_num);

  // Gets the notify block from the notify ID. This ID will not change when
  // slices get remapped to new processor affinities.
  NotifyBlock* GetNotifyBlock(UINT notify_id) const;

  // Gets the notify block from the message ID. This ID will change when slices
  // get remapped to new processor affinities, and is the ID provided by the
  // interrupt handler.
  NotifyBlock* GetMappedNotifyBlock(UINT message_id) const;

  // Changes a notify block's processor affinity to match the message info
  // indexed by message ID.
  void ConfigureMsiXTableEntry(UINT32 notify_id, UINT32 message_id,
                               UINT32 slice, NotifyBlock* block);

  // Validates or updates the processor affinity for a given rx slice.
  void UpdateRxProcessorAffinity(UINT32 slice_num, PROCESSOR_NUMBER processor);

  UINT32 num_notify_blocks_;
  UINT32 mgmt_msix_index_;
  const IO_INTERRUPT_MESSAGE_INFO* msi_table_;
  NDIS_HANDLE miniport_handle_;

  QueueConfig* rx_config_;
  QueueConfig* tx_config_;

  // Device mapped memory address between device and driver for notify blocks.
  SharedMemory<NotifyBlock> dma_notify_blocks_;
  // When memory gets allocated, it is not guaranteed to be page size aligned.
  // So driver allocate will allocate one more block than expected and this
  // value saves the adjusted/page-aligned start address for the notify_blocks.
  UINT64 notify_blocks_physical_address_;
  // Virtual Address for the adjusted notify_blocks. It points to the same
  // memory location with the notify_blocks_physical_address_ and gets used
  // insider driver.
  NotifyBlock* notify_blocks_;
  // A mapping of message IDs to notify block IDs. When using RSS Windows may
  // load balance via the indirection table, which requires us to change the
  // processor affinity of a given notify block. When the MSI-X table entry
  // is swapped to change processor affinity, the message ID provided during
  // interrupts will change too.
  UINT32* message_id_to_notify_id_map_;
};

#endif  // NOTIFY_MANAGER_H_
