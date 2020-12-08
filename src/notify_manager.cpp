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

#include "notify_manager.h"  // NOLINT: include directory

#include "utils.h"  // NOLINT: include directory

#include "notify_manager.tmh"  // NOLINT: include directory

namespace {
constexpr UINT32 kNotifyBlockMsixBaseIndex = 0;
}  // namespace

NotifyManager::~NotifyManager() { Release(); }

bool NotifyManager::Init(NDIS_HANDLE miniport_handle,
                         const IO_INTERRUPT_MESSAGE_INFO* msi_table,
                         QueueConfig* tx_config, QueueConfig* rx_config) {
  NT_ASSERT(miniport_handle != nullptr);
  NT_ASSERT(msi_table != nullptr);

  miniport_handle_ = miniport_handle;
  msi_table_ = msi_table;
  UINT32 num_msi_vectors = msi_table_->MessageCount;

  // We need at least 3 to hold one for mgt queue, one tx and one rx.
  NT_ASSERT(num_msi_vectors >= 3);
  // Assert init is called for the first time or only after Reset.
  NT_ASSERT(num_notify_blocks_ == 0);

  tx_config_ = tx_config;
  rx_config_ = rx_config;

  message_id_to_notify_id_map_ =
      AllocateMemory<UINT32>(miniport_handle_, num_msi_vectors);
  if (message_id_to_notify_id_map_ == nullptr) {
    DEBUGP(GVNIC_ERROR,
           "[%s] ERROR: Unable to allocate %d bytes to map message IDs to "
           "notify IDs.",
           __FUNCTION__, num_msi_vectors * sizeof(UINT32));
    return false;
  } else {
    // Before any affinity remapping, message IDs are the same as notify IDs.
    for (UINT32 i = 0; i < num_msi_vectors; i++) {
      message_id_to_notify_id_map_[i] = i;
    }
  }

  UINT32 expected_notify_blocks_for_transmission =
      tx_config_->num_slices + rx_config_->num_slices;
  if (num_msi_vectors > (expected_notify_blocks_for_transmission + 1)) {
    // The driver can allocate more MSI-X entries than the device expects to
    // allow changing a slice's processor affinity during runtime. These extra
    // entries must not be reported to the device. The last standard entry will
    // still be used for the management block.
    mgmt_msix_index_ = expected_notify_blocks_for_transmission;
    num_notify_blocks_ = expected_notify_blocks_for_transmission;

    DEBUGP(GVNIC_INFO,
           "[%s] The driver successfully allocated more MSI-X entries than "
           "required to allow for dynamic affinity swapping. %d entries were "
           "expected, and %d entries were provided.",
           __FUNCTION__, expected_notify_blocks_for_transmission + 1,
           num_msi_vectors);
  } else {
    // Use the last interrupt vector for management.
    mgmt_msix_index_ = num_msi_vectors - 1;
    num_notify_blocks_ = num_msi_vectors - 1;
  }

  if (expected_notify_blocks_for_transmission > num_notify_blocks_) {
    // All Tx/Rx traffic class shares one notify block with same slice number.
    // Code calculates how many msi vectors each traffic class
    // can has and then adjust the max slices number accordingly.
    int vecs_per_queue = num_notify_blocks_ / 2;
    int vecs_left = num_notify_blocks_ % 2;

    // In addition to vecs_per_queue, distribute any vectors left across all rx
    // traffic class.
    UINT32 max_rx_slices_with_msi_vector = vecs_per_queue + vecs_left;
    rx_config_->num_slices =
        min(rx_config_->num_slices, max_rx_slices_with_msi_vector);

    // Give all the vectors left to tx.
    UINT32 max_tx_slices_with_msi_vector = vecs_per_queue;
    tx_config_->num_slices =
        min(tx_config_->num_slices, max_tx_slices_with_msi_vector);

    DEBUGP(
        GVNIC_WARNING,
        "[%s] WARNING: Do not have desired msix %u, only enabled %u, adjusting "
        "tx slices to %u and rx slices to %u",
        __FUNCTION__, expected_notify_blocks_for_transmission,
        num_notify_blocks_, tx_config_->num_slices, rx_config_->num_slices);
  }

  // we allocate one more block to have buffer to do cache line alignment.
  if (!dma_notify_blocks_.Allocate(miniport_handle_, num_notify_blocks_ + 1)) {
    return false;
  }

  UINT cacheline_offset = GetCacheAlignOffset(
      dma_notify_blocks_.physical_address().QuadPart, kCacheLineSize);

  // Move the virtual address by offset bytes.
  notify_blocks_ = reinterpret_cast<NotifyBlock*>(
      reinterpret_cast<char*>(dma_notify_blocks_.virtual_address()) +
      cacheline_offset);

  notify_blocks_physical_address_ =
      dma_notify_blocks_.physical_address().QuadPart + cacheline_offset;

  DEBUGP(GVNIC_INFO,
         "[%s] Get allocated notify blocks with physical addr %#llx, "
         "calculated offset %#x, adjusted physical addr %#llx",
         __FUNCTION__, dma_notify_blocks_.physical_address().QuadPart,
         cacheline_offset, notify_blocks_physical_address_);

  for (UINT i = 0; i < num_notify_blocks_; i++) {
    notify_blocks_[i].num_rx_rings = 0;
    notify_blocks_[i].rx_rings =
        AllocateMemory<RxRing*>(miniport_handle_, rx_config_->rx.num_groups);
    if (notify_blocks_[i].rx_rings == nullptr) {
      return false;
    }
    notify_blocks_[i].processor_affinity =
        msi_table_->MessageInfo[i].TargetProcessorSet;
  }

  return true;
}

void NotifyManager::Release() {
  for (UINT i = 0; i < num_notify_blocks_; i++) {
    FreeMemory(notify_blocks_[i].rx_rings);
    notify_blocks_[i].rx_rings = nullptr;
  }

  FreeMemory(message_id_to_notify_id_map_);
  message_id_to_notify_id_map_ = nullptr;

  num_notify_blocks_ = 0;
  mgmt_msix_index_ = 0;
  tx_config_ = nullptr;
  rx_config_ = nullptr;
  msi_table_ = nullptr;
  miniport_handle_ = nullptr;

  dma_notify_blocks_.Release();
}

UINT32 NotifyManager::RegisterRxRing(UINT32 slice_num, RxRing* rx_ring) {
  UINT32 notify_id = GetRxNotifyId(slice_num);
  NotifyBlock* notify_block = GetNotifyBlock(notify_id);

  NT_ASSERT(notify_block->num_rx_rings + 1 <= rx_config_->rx.num_groups);

  UINT32 num_rx_ring = notify_block->num_rx_rings;
  notify_block->rx_rings[num_rx_ring] = rx_ring;
  notify_block->num_rx_rings++;

  return notify_id;
}

UINT32 NotifyManager::RegisterTxRing(UINT32 slice_num, TxRing* tx_ring) {
  UINT32 notify_id = GetTxNotifyId(slice_num);
  NotifyBlock* notify_block = GetNotifyBlock(notify_id);

  NT_ASSERT(notify_block->tx_ring == nullptr);

  notify_block->tx_ring = tx_ring;

  return notify_id;
}

void NotifyManager::Reset() {
  for (UINT i = 0; i < num_notify_blocks_; i++) {
    for (UINT j = 0; j < notify_blocks_[i].num_rx_rings; j++) {
      notify_blocks_[i].rx_rings[j] = nullptr;
    }

    notify_blocks_[i].num_rx_rings = 0;
    notify_blocks_[i].tx_ring = nullptr;
  }
}

UINT32 NotifyManager::GetRxRingCount(UINT32 message_id) const {
  NotifyBlock* notify_block = GetMappedNotifyBlock(message_id);

  return notify_block->num_rx_rings;
}

RxRing* NotifyManager::GetRxRing(UINT32 message_id, UINT32 ring_idx) const {
  NotifyBlock* notify_block = GetMappedNotifyBlock(message_id);

  NT_ASSERT(ring_idx < notify_block->num_rx_rings);
  return notify_block->rx_rings[ring_idx];
}

TxRing* NotifyManager::GetTxRing(UINT32 message_id) const {
  NotifyBlock* notify_block = GetMappedNotifyBlock(message_id);
  return notify_block->tx_ring;
}

UINT32 NotifyManager::notify_block_msi_base_index() const {
  return kNotifyBlockMsixBaseIndex;
}

UINT32 NotifyManager::GetInterruptDoorbellIndex(UINT32 message_id) const {
  NotifyBlock* notify_block = GetMappedNotifyBlock(message_id);
  return RtlUlongByteSwap(notify_block->irq_db_index);
}

UINT32 NotifyManager::GetTxNotifyId(UINT32 slice_num) {
  NT_ASSERT(num_notify_blocks_);
  return kNotifyBlockMsixBaseIndex + slice_num;
}

UINT32 NotifyManager::GetRxNotifyId(UINT32 slice_num) {
  NT_ASSERT(num_notify_blocks_);
  return kNotifyBlockMsixBaseIndex + tx_config_->num_slices + slice_num;
}

void NotifyManager::UpdateRxProcessorAffinities(
    const RSSConfiguration& rss_config) {
  if (rss_config.is_enabled()) {
    for (UINT32 i = 0; i < rss_config.indirection_table_size(); i++) {
      UINT32 rx_slice = rss_config.GetIndirectionTableEntry(i);
      const PROCESSOR_NUMBER& processor = rss_config.get_indirection_table()[i];
      UpdateRxProcessorAffinity(rx_slice, processor);
    }
  } else {
    // Reset the rx slice processor affinities if they have been changed by an
    // indirection table.
    for (UINT32 slice = 0; slice < rx_config_->num_slices; slice++) {
      UINT32 notify_id = GetRxNotifyId(slice);
      NotifyBlock* block = GetNotifyBlock(notify_id);
      if (block->processor_affinity !=
          msi_table_->MessageInfo[notify_id].TargetProcessorSet) {
        ConfigureMsiXTableEntry(notify_id, notify_id, slice, block);
      }
    }
  }
}

void NotifyManager::UpdateRxProcessorAffinity(UINT32 slice_num,
                                              PROCESSOR_NUMBER processor) {
  KAFFINITY new_affinity = (1ull << processor.Number);
  UINT32 notify_id = GetRxNotifyId(slice_num);
  NotifyBlock* block = GetNotifyBlock(notify_id);
  if (block->processor_affinity == new_affinity) {
    // In the most common scenario, the slice chosen for the RSS processor
    // in the indirection table already has the matching affinity.
    return;
  }

  // Only MSI-X entries already used for rx slices, and the additional MSI-X
  // entries requested during initialization (which are stored directly after
  // the management queue index) can be used for affinity swapping.
  for (UINT32 message_id = GetRxNotifyId(/*slice_num=*/0);
       message_id < msi_table_->MessageCount; message_id++) {
    if (message_id == mgmt_msix_index_) {
      continue;
    }
    if (msi_table_->MessageInfo[message_id].TargetProcessorSet ==
        new_affinity) {
      ConfigureMsiXTableEntry(notify_id, message_id, slice_num, block);
      return;
    }
  }

  DEBUGP(GVNIC_WARNING,
         "[%s] WARNING: Rx slice %u has affinity %#llX while the indirection "
         "table expects affinity %#llX. There were no available MSI-X entries "
         "with the correct affinity to switch to, so packets may be indicated "
         "on the wrong processor.",
         __FUNCTION__, slice_num, block->processor_affinity, new_affinity);
}

void NotifyManager::ConfigureMsiXTableEntry(UINT32 notify_id, UINT32 message_id,
                                            UINT32 slice, NotifyBlock* block) {
  NDIS_MSIX_CONFIG_PARAMETERS param;
  param.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
  param.Header.Revision = NDIS_MSIX_CONFIG_PARAMETERS_REVISION_1;
  param.Header.Size = NDIS_SIZEOF_MSIX_CONFIG_PARAMETERS_REVISION_1;

  param.ConfigOperation = NdisMSIXTableConfigSetTableEntry;
  param.TableEntry = notify_id;
  param.MessageNumber = message_id;

  KAFFINITY old_affinity = block->processor_affinity;
  KAFFINITY new_affinity =
      msi_table_->MessageInfo[message_id].TargetProcessorSet;

  NDIS_STATUS status = NdisMConfigMSIXTableEntry(miniport_handle_, &param);
  if (status != NDIS_STATUS_SUCCESS) {
    DEBUGP(GVNIC_ERROR,
           "[%s] ERROR: Unable to change the affinity of rx slice %u from "
           "%#llX to %#llX. The table entry to change was %u, and the message "
           "number to use was %u.",
           __FUNCTION__, slice, old_affinity, new_affinity, notify_id,
           message_id);
    return;
  }

  block->processor_affinity = new_affinity;
  message_id_to_notify_id_map_[message_id] = notify_id;

  DEBUGP(GVNIC_INFO,
         "[%s] Changed the affinity for rx slice %u from %#llX to %#llX.",
         __FUNCTION__, slice, old_affinity, new_affinity);
}

NotifyBlock* NotifyManager::GetMappedNotifyBlock(UINT message_id) const {
  NT_ASSERT(message_id < msi_table_->MessageCount);
  UINT32 notify_id = message_id_to_notify_id_map_[message_id];
  return GetNotifyBlock(notify_id);
}

NotifyBlock* NotifyManager::GetNotifyBlock(UINT notify_id) const {
  NT_ASSERT(notify_id < num_notify_blocks_);
  return &notify_blocks_[notify_id];
}
