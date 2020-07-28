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

#include "gvnic_pci_device.h"  // NOLINT: include directory

#include "abi.h"                    // NOLINT: include directory
#include "adapter_configuration.h"  // NOLINT: include directory
#include "adapter_resource.h"       // NOLINT: include directory
#include "adapter_statistics.h"     // NOLINT: include directory
#include "offload.h"                // NOLINT: include directory
#include "ring_base.h"              // NOLINT: include directory
#include "rx_ring.h"                // NOLINT: include directory
#include "spin_lock_context.h"      // NOLINT: include directory
#include "trace.h"                  // NOLINT: include directory
#include "tx_ring.h"                // NOLINT: include directory
#include "utils.h"                  // NOLINT: include directory

#include "gvnic_pci_device.tmh"  // NOLINT: trace message header

namespace {
constexpr UINT kMaxTxTrafficClass = 8;
constexpr UINT kMaxVersionLength = 1024;  // Device accept max 1024
constexpr char kVersionPrefix[] = "NDIS-";

// By default, we only use one traffic class and user/agent can overwrite this
// value later.
constexpr UINT kDefaultTxTrafficClassCount = 1;

// Avoid queue page list id collision, apply this mask for rx ring to flip the
// first bit to 1.
constexpr int kRxQueuePageListIdMask = 1 << 31;

void DumpProcTrafficClassToTxRingMapping(UINT32* mapping, UINT32 max_slice,
                                         UINT32 max_tc) {
  DEBUGP(GVNIC_VERBOSE,
         "[%s] Mapping from slice, tc to tx ring index:", __FUNCTION__);
  for (UINT32 tc = 0; tc < max_tc; tc++) {
    for (UINT32 slice = 0; slice < max_slice; slice++) {
      DEBUGP(GVNIC_VERBOSE, "[%s] (slice: %d, tc: %d) -> (tx_ring: %d)",
             __FUNCTION__, slice, tc, mapping[tc * max_slice + slice]);
    }
  }
}
}  // namespace

GvnicPciDevice::~GvnicPciDevice() {
  PAGED_CODE();

  Release();
}

NDIS_STATUS GvnicPciDevice::Init(AdapterResources* resources,
                                 AdapterStatistics* statistics,
                                 const AdapterConfiguration& configuration) {
  PAGED_CODE();
  DEBUGP(GVNIC_VERBOSE, "---> GvnicPciDevice::Initialize\n");

  resources_ = resources;
  statistics_ = statistics;
  NdisAllocateSpinLock(&rx_checksum_enabled_spin_lock_);
  NdisAllocateSpinLock(&eth_header_len_spin_lock_);
  NdisAllocateSpinLock(&rss_config_spin_lock_);
  UpdateRxChecksumSetting(false);
  UpdateTxPacketHeaderLength({kEthAddrLen, kEthAddrLen});

  SetHardwareDefaultOffloadCapability(&hardware_offload_capabilities_);
  SetDriverInfo();

  NDIS_STATUS status = LoadDeviceConfiguration();
  if (status == NDIS_STATUS_SUCCESS) {
    status = LoadAdapterConfiguration(configuration);
  }
  if (status == NDIS_STATUS_SUCCESS) {
    status = ConfigureDeviceResource();
  }

  rss_config_.Init(configuration.is_rss_enabled(), rx_config_.num_slices);
  DEBUGP(GVNIC_VERBOSE, "<--- GvnicPciDevice::Initialize status 0x%08x\n",
         status);
  return status;
}

void GvnicPciDevice::Release() {
  PAGED_CODE();

  notify_manager_.Release();
  UnregisterRings();
  FreeRings();

  admin_queue_.DeconfigureDeviceResource();
  admin_queue_.Release();
  counter_array_.Release();
}

void GvnicPciDevice::Reset(AdapterResources* resources,
                           AdapterStatistics* statistics,
                           const AdapterConfiguration& configuration) {
  Release();
  Init(resources, statistics, configuration);
}

NDIS_STATUS GvnicPciDevice::LoadAdapterConfiguration(
    const AdapterConfiguration& configuration) {
  PAGED_CODE();

  if (configuration.is_mac_configured()) {
    ETH_COPY_NETWORK_ADDRESS(current_mac_, configuration.mac());
  }

  max_packet_size_.max_data_size = configuration.mtu();
  max_packet_size_.max_full_size =
      max_packet_size_.max_data_size + kEthHeaderSize;

  SetOffloadConfiguration(configuration, &offload_configuration_);

  // Adjust number of queues if value is overwritten in the adapter setting.
  if (configuration.num_tx_queue() != 0) {
    // tx_config_.num_queue is the max queue supported by the device.
    // Only accept user setting if less than the limit. Same for rx_ring.
    tx_config_.num_queues =
        min(tx_config_.num_queues, configuration.num_tx_queue());
    DEBUGP(GVNIC_INFO, "[%s] Adjust number of tx queues to: %d", __FUNCTION__,
           tx_config_.num_queues);
  }

  if (configuration.num_rx_queue() != 0) {
    rx_config_.num_queues =
        min(rx_config_.num_queues, configuration.num_rx_queue());
    DEBUGP(GVNIC_INFO, "[%s] Adjust number of rx queues to: %d", __FUNCTION__,
           rx_config_.num_queues);
  }

  return NDIS_STATUS_SUCCESS;
}

void GvnicPciDevice::SetDriverInfo() {
  PAGED_CODE();

  int version[] = {MAJOR_DRIVER_VERSION, MINOR_DRIVER_VERSION, RELEASE_VERSION,
                   RELEASE_VERSION_QEF};

  UCHAR version_str[kMaxVersionLength];

  // Going backwards so it is easier to convert int into ASCII char array.
  int version_str_start = kMaxVersionLength - 1;

  for (int i = 3; i >= 0 && version_str_start >= 0; i--) {
    version_str[version_str_start--] = '.';
    int version_num = version[i];

    do {
      if (version_str_start < 0) {
        break;
      }

      version_str[version_str_start--] = '0' + version_num % 10;
      version_num /= 10;
    } while (version_num > 0);
  }

  // Add Version Prefix.
  // -2 as array is zero indexed and skip the line ending.
  for (int i = sizeof(kVersionPrefix) / sizeof(char) - 2;
       i >= 0 && version_str_start >= 0; i--) {
    version_str[version_str_start--] = kVersionPrefix[i];
  }

  // Move the start pointer to the first char.
  version_str_start++;

  // Replace the last '.' with '\n'.
  version_str[kMaxVersionLength - 1] = '\n';

  for (int i = version_str_start; i < kMaxVersionLength; i++) {
    resources_->WriteRegister(kConfigStatusRegister,
                              FIELD_OFFSET(GvnicDeviceConfig, driver_version),
                              version_str[i]);
  }
}

NDIS_STATUS GvnicPciDevice::LoadDeviceConfiguration() {
  PAGED_CODE();

  ULONG value_buffer;
  resources_->ReadRegister(kConfigStatusRegister,
                           FIELD_OFFSET(GvnicDeviceConfig, max_tx_queues),
                           &value_buffer);

  // GVNIC is big-endian device. Need to reverse the order of bytes.
  device_params_.max_tx_queues = RtlUlongByteSwap(value_buffer);
  DEBUGP(GVNIC_INFO, "[%s] Read max tx from Bar0: %#X", __FUNCTION__,
         device_params_.max_tx_queues);

  resources_->ReadRegister(kConfigStatusRegister,
                           FIELD_OFFSET(GvnicDeviceConfig, max_rx_queues),
                           &value_buffer);
  device_params_.max_rx_queues = RtlUlongByteSwap(value_buffer);
  DEBUGP(GVNIC_INFO, "[%s] Read max rx from Bar0: %#X", __FUNCTION__,
         device_params_.max_rx_queues);

  NDIS_STATUS status = admin_queue_.Init(resources_);
  if (status != NDIS_STATUS_SUCCESS) {
    return status;
  }

  status = admin_queue_.DescribeDevice(&device_params_.descriptor);
  if (status != NDIS_STATUS_SUCCESS) {
    return status;
  }

  ETH_COPY_NETWORK_ADDRESS(permanent_mac_, device_params_.descriptor.mac);
  ETH_COPY_NETWORK_ADDRESS(current_mac_, device_params_.descriptor.mac);

  SetTransmitQueueConfig();

  return status;
}

void GvnicPciDevice::SetTransmitQueueConfig() {
  PAGED_CODE();

  tx_config_.max_traffic_class =
      min(device_params_.max_tx_queues, kMaxTxTrafficClass);
  tx_config_.max_slices = static_cast<int>(GetSystemProcessorCount());
  tx_config_.array_size = tx_config_.max_traffic_class * tx_config_.max_slices;
  tx_config_.max_queues =
      min(tx_config_.array_size, device_params_.max_tx_queues);

  tx_config_.num_queues = tx_config_.max_queues;
  tx_config_.num_slices =
      min(device_params_.descriptor.default_num_slices, tx_config_.max_slices);
  tx_config_.num_traffic_class = kDefaultTxTrafficClassCount;
  tx_config_.num_descriptors = device_params_.descriptor.tx_queue_size;
  tx_config_.pages_per_queue_page_list =
      device_params_.descriptor.tx_pages_per_qpl;

  DEBUGP(GVNIC_INFO,
         "[%s] TX slices %d, max slices %d, tcs %d, max tcs %d, array size %d, "
         "max queues %d, descriptor %d, pages per queue %d",
         __FUNCTION__, tx_config_.num_slices, tx_config_.max_slices,
         tx_config_.num_traffic_class, tx_config_.max_traffic_class,
         tx_config_.array_size, tx_config_.max_queues,
         tx_config_.num_descriptors, tx_config_.pages_per_queue_page_list);

  // Device pushes the number of rx traffic class to the driver. Code keeps both
  // max and number of traffic class to be same and const. User cannot adjust
  // this value later.
  rx_config_.max_traffic_class = rx_config_.num_traffic_class =
      device_params_.descriptor.num_rx_groups;
  rx_config_.max_slices = min(device_params_.descriptor.default_num_slices,
                              static_cast<int>(GetSystemProcessorCount()));
  rx_config_.array_size = rx_config_.max_traffic_class * rx_config_.max_slices;
  rx_config_.max_queues =
      min(rx_config_.array_size, device_params_.max_rx_queues);

  rx_config_.num_queues = rx_config_.max_queues;
  rx_config_.num_slices = rx_config_.max_slices;
  rx_config_.num_descriptors = device_params_.descriptor.rx_queue_size;
  rx_config_.pages_per_queue_page_list =
      device_params_.descriptor.rx_queue_size;

  // Pages per QPL must match the queue size for rx as each descriptor uses
  // a single page.
  NT_ASSERT(rx_config_.pages_per_queue_page_list == rx_config_.num_descriptors);

  DEBUGP(GVNIC_INFO,
         "[%s] RX slices %d, max slices %d, tcs %d, max tcs %d, array size %d, "
         "max queues %d, descriptor %d, pages per queue %d",
         __FUNCTION__, rx_config_.num_slices, rx_config_.max_slices,
         rx_config_.num_traffic_class, rx_config_.max_traffic_class,
         rx_config_.array_size, rx_config_.max_queues,
         rx_config_.num_descriptors, rx_config_.pages_per_queue_page_list);
}

NDIS_STATUS GvnicPciDevice::ConfigureDeviceResource() {
  PAGED_CODE();

  if (!counter_array_.Allocate(resources_->miniport_handle(),
                               device_params_.descriptor.event_counters)) {
    return NDIS_STATUS_RESOURCES;
  }

  IO_INTERRUPT_MESSAGE_INFO* msi_table = resources_->msi_info_table();
  for (UINT i = 0; i < msi_table->MessageCount; i++) {
    DEBUGP(GVNIC_INFO, "[%s] MSI message%d=%#X=>%#llX, vector=%d, target=%#llX",
           __FUNCTION__, i, msi_table->MessageInfo[i].MessageData,
           msi_table->MessageInfo[i].MessageAddress.QuadPart,
           msi_table->MessageInfo[i].Vector,
           msi_table->MessageInfo[i].TargetProcessorSet);
  }

  if (!notify_manager_.Init(resources_->miniport_handle(),
                            msi_table->MessageCount, &tx_config_,
                            &rx_config_)) {
    return NDIS_STATUS_RESOURCES;
  }

  return admin_queue_.ConfigureDeviceResource(
      counter_array_.physical_address().QuadPart,
      device_params_.descriptor.event_counters,
      notify_manager_.notify_blocks_physical_address(),
      notify_manager_.num_notify_blocks(), sizeof(NotifyBlock),
      notify_manager_.notify_block_msi_base_index());
}

void GvnicPciDevice::SendNetBufferLists(PNET_BUFFER_LIST net_buffer_list,
                                        bool is_dpc_level) {
  ULONG proc_index = GetCurrentProcessorIndex();

  while (net_buffer_list) {
    // No plan to use tx traffic class now.
    // NDIS_NET_BUFFER_LIST_8021Q_INFO qos_info;
    // qos_info.Value =
    //     NET_BUFFER_LIST_INFO(net_buffer_list, Ieee8021QNetBufferListInfo);

    // NT_ASSERT(qos_info.TagHeader.UserPriority == 0);
    // UINT32 traffic_class =
    //     ignore_flow_table_ ? 0 : qos_info.TagHeader.UserPriority;

    TxRing* tx_ring = GetTxRing(proc_index, /*traffic_class=*/0);
    NT_ASSERT(tx_ring->is_init());

    NET_BUFFER_LIST* next_net_buffer_list =
        NET_BUFFER_LIST_NEXT_NBL(net_buffer_list);

    // Break the link between the NET_BUFFER_LIST so the tx_ring won't
    // accidentally access the next NET_BUFFER_LIST in the code. They could
    // have different traffic class and should be handled in another tx ring.
    NET_BUFFER_LIST_NEXT_NBL(net_buffer_list) = nullptr;

    tx_ring->SendBufferList(net_buffer_list, is_dpc_level);
    net_buffer_list = next_net_buffer_list;
  }
}

NDIS_STATUS GvnicPciDevice::Pause() {
  PAGED_CODE();
  NDIS_STATUS status = UnregisterRings();

  if (status != NDIS_STATUS_SUCCESS) {
    return status;
  }

  FreeRings();
  SetLinkState(MediaConnectStateDisconnected);

  return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS GvnicPciDevice::Restart() {
  PAGED_CODE();
  NDIS_STATUS status = AllocateRings();
  if (status != NDIS_STATUS_SUCCESS) {
    FreeRings();
    SetLinkState(MediaConnectStateDisconnected);
    return status;
  }

  status = RegisterRings();
  if (status == NDIS_STATUS_SUCCESS) {
    SetLinkState(MediaConnectStateConnected);
    SetSliceTrafficClassToTxRingMapping();
  }

  return status;
}

void GvnicPciDevice::Shutdown() {}

void GvnicPciDevice::SurpriseRemove() {}

void GvnicPciDevice::HandleManagementQueueRequest() {
  ULONG value_buffer;
  resources_->ReadRegister(kConfigStatusRegister,
                           FIELD_OFFSET(GvnicDeviceConfig, dev_status),
                           &value_buffer);
  UINT32 device_status = RtlUlongByteSwap(value_buffer);
  DEBUGP(GVNIC_INFO, "[%s] Device status %#X.", __FUNCTION__, device_status);

  if (device_status & kDeviceStatusIgnoreFlowTable) {
    if (!ignore_flow_table_) {
      DEBUGP(GVNIC_INFO, "[%s] Ignore Flow Table bit set.", __FUNCTION__);
      ignore_flow_table_ = true;
    }
  } else {
    if (ignore_flow_table_) {
      DEBUGP(GVNIC_INFO, "[%s] Ignore Flow Table bit cleared.", __FUNCTION__);
      ignore_flow_table_ = false;
    }
  }

  if (device_status & kDeviceStatusReset) {
    DEBUGP(GVNIC_ERROR,
           "[%s] ERROR: PCI hard reset from driver is not supported",
           __FUNCTION__);
  }
}

NDIS_STATUS GvnicPciDevice::AllocateRings() {
  DEBUGP(GVNIC_INFO, "[%s] Allocate transmit ring resources.", __FUNCTION__);
  PAGED_CODE();
  slice_tc_to_tx_ring_map_ = AllocateMemory<UINT32>(
      resources_->miniport_handle(), tx_config_.array_size);
  if (!slice_tc_to_tx_ring_map_) {
    DEBUGP(GVNIC_ERROR,
           "[%s] ERROR: Memory allocation failed for slice_tc_to_tx_ring_map.",
           __FUNCTION__);
    return NDIS_STATUS_RESOURCES;
  }

  // Allocate tx resources
  tx_rings_ = AllocateMemory<TxRing>(resources_->miniport_handle(),
                                     tx_config_.array_size);

  if (!tx_rings_) {
    DEBUGP(GVNIC_ERROR, "[%s] ERROR: Memory allocation failed for tx rings.",
           __FUNCTION__);
    return NDIS_STATUS_RESOURCES;
  }

  tx_queue_page_lists_ = AllocateMemory<QueuePageList>(
      resources_->miniport_handle(), tx_config_.array_size);

  if (!tx_queue_page_lists_) {
    DEBUGP(GVNIC_ERROR,
           "[%s] ERROR: Memory allocation failed for tx queue page list.",
           __FUNCTION__);
    return NDIS_STATUS_RESOURCES;
  }

  if (!InitTxRings()) {
    return NDIS_STATUS_RESOURCES;
  }

  // Allocate rx resources
  rx_rings_ = AllocateMemory<RxRing>(resources_->miniport_handle(),
                                     rx_config_.array_size);

  if (!rx_rings_) {
    DEBUGP(GVNIC_ERROR, "[%s] ERROR: Memory allocation failed for rx rings.",
           __FUNCTION__);
    return NDIS_STATUS_RESOURCES;
  }

  rx_queue_page_lists_ = AllocateMemory<QueuePageList>(
      resources_->miniport_handle(), rx_config_.array_size);

  if (!rx_queue_page_lists_) {
    DEBUGP(GVNIC_ERROR,
           "[%s] ERROR: Memory allocation failed for tx queue page list.",
           __FUNCTION__);
    return NDIS_STATUS_RESOURCES;
  }

  if (!InitRxRings()) {
    return NDIS_STATUS_RESOURCES;
  }

  // There is a chance that previous Value update is not propagated to rings
  // since the rings are not setup yet. Resetting those values.
  UpdateRxChecksumSetting(rx_checksum_enabled_);
  UpdateTxPacketHeaderLength(eth_header_len_);
  UpdateRxRssConfig();

  return NDIS_STATUS_SUCCESS;
}

bool GvnicPciDevice::InitTxRings() {
  PAGED_CODE();

  UINT tx_ring_count = 0;
  for (UINT tc = 0; tc < tx_config_.num_traffic_class; tc++) {
    for (UINT slice = 0; slice < tx_config_.num_slices; slice++) {
      if (tx_ring_count == tx_config_.num_queues) {
        return true;
      }

      UINT tx_ring_id = RingBase::GetRingId(tx_config_.max_slices, slice, tc);
      QueuePageList* tx_queue_page_list = &tx_queue_page_lists_[tx_ring_id];

      if (!tx_queue_page_list->Init(tx_ring_id,
                                    tx_config_.pages_per_queue_page_list,
                                    resources_->miniport_handle())) {
        return false;
      }

      TxRing* tx = &tx_rings_[tx_ring_id];

      UINT notify_id = notify_manager_.RegisterTxRing(slice, tx);
      if (!tx->Init(tx_ring_id, slice, tc, tx_config_.num_descriptors,
                    tx_queue_page_list, notify_id, resources_, statistics_,
                    counter_array_.virtual_address())) {
        return false;
      }

      tx_ring_count++;
    }
  }

  return true;
}

bool GvnicPciDevice::InitRxRings() {
  PAGED_CODE();

  UINT rx_ring_count = 0;
  for (UINT tc = 0; tc < rx_config_.num_traffic_class; tc++) {
    for (UINT slice = 0; slice < rx_config_.num_slices; slice++) {
      if (rx_ring_count == rx_config_.num_queues) {
        return true;
      }

      UINT rx_ring_id = RingBase::GetRingId(rx_config_.max_slices, slice, tc);
      QueuePageList* rx_queue_page_list = &rx_queue_page_lists_[rx_ring_id];

      if (!rx_queue_page_list->Init(rx_ring_id | kRxQueuePageListIdMask,
                                    rx_config_.pages_per_queue_page_list,
                                    resources_->miniport_handle())) {
        return false;
      }

      RxRing* rx = &rx_rings_[rx_ring_id];
      UINT notify_id = notify_manager_.RegisterRxRing(slice, rx);

      if (!rx->Init(rx_ring_id, slice, tc, rx_config_.num_descriptors,
                    rx_queue_page_list, notify_id, resources_, statistics_,
                    counter_array_.virtual_address())) {
        return false;
      }

      rx_ring_count++;
    }
  }

  return true;
}

void GvnicPciDevice::FreeRings() {
  DEBUGP(GVNIC_INFO, "[%s] Free all allocated rings.", __FUNCTION__);
  PAGED_CODE();

  notify_manager_.Reset();

  if (tx_rings_ != nullptr) {
    for (UINT32 i = 0; i < tx_config_.array_size; i++) {
      tx_rings_[i].Release();
    }
    FreeMemory(tx_rings_);
    tx_rings_ = nullptr;
  }

  if (tx_queue_page_lists_ != nullptr) {
    for (UINT32 i = 0; i < tx_config_.array_size; i++) {
      tx_queue_page_lists_[i].Release();
    }
    FreeMemory(tx_queue_page_lists_);
    tx_queue_page_lists_ = nullptr;
  }

  if (rx_rings_ != nullptr) {
    for (UINT32 i = 0; i < rx_config_.array_size; i++) {
      rx_rings_[i].Release();
    }
    FreeMemory(rx_rings_);
    rx_rings_ = nullptr;
  }

  if (rx_queue_page_lists_ != nullptr) {
    for (UINT32 i = 0; i < rx_config_.array_size; i++) {
      rx_queue_page_lists_[i].Release();
    }
    FreeMemory(rx_queue_page_lists_);
    rx_queue_page_lists_ = nullptr;
  }

  if (slice_tc_to_tx_ring_map_ != nullptr) {
    FreeMemory(slice_tc_to_tx_ring_map_);
    slice_tc_to_tx_ring_map_ = nullptr;
  }
}

NDIS_STATUS GvnicPciDevice::RegisterRings() {
  DEBUGP(GVNIC_INFO, "[%s] Register rings with device.", __FUNCTION__);
  PAGED_CODE();

  NDIS_STATUS status = NDIS_STATUS_SUCCESS;
  for (UINT32 i = 0; i < tx_config_.array_size; i++) {
    if (!tx_rings_[i].is_init()) {
      continue;
    }

    status = admin_queue_.RegisterPageList(*tx_rings_[i].queue_page_list(),
                                           resources_->miniport_handle());

    if (status != NDIS_STATUS_SUCCESS) {
      return status;
    }

    status = admin_queue_.CreateTransmitQueue(tx_rings_[i]);

    if (status != NDIS_STATUS_SUCCESS) {
      return status;
    }
  }

  for (UINT32 i = 0; i < rx_config_.array_size; i++) {
    if (!rx_rings_[i].is_init()) {
      continue;
    }

    status = admin_queue_.RegisterPageList(*rx_rings_[i].queue_page_list(),
                                           resources_->miniport_handle());

    if (status != NDIS_STATUS_SUCCESS) {
      return status;
    }

    status = admin_queue_.CreateReceiveQueue(rx_rings_[i]);

    if (status != NDIS_STATUS_SUCCESS) {
      return status;
    }

    rx_rings_[i].SetInitFreeSlot();
  }

  return status;
}

NDIS_STATUS GvnicPciDevice::UnregisterRings() {
  DEBUGP(GVNIC_INFO, "[%s] Unregister rings with device.", __FUNCTION__);
  PAGED_CODE();

  NDIS_STATUS status = NDIS_STATUS_SUCCESS;
  // PageList is used inside tx/rx queue, so driver call
  // DestoryTransmit/ReceiveQueue first and then UnregisterPageList.
  if (tx_rings_ != nullptr) {
    for (UINT32 i = 0; i < tx_config_.array_size; i++) {
      if (!tx_rings_[i].is_init()) {
        continue;
      }

      status = admin_queue_.DestroyTransmitQueue(tx_rings_[i]);

      if (status != NDIS_STATUS_SUCCESS) {
        return status;
      }

      status = admin_queue_.UnregisterPageList(*tx_rings_[i].queue_page_list());

      if (status != NDIS_STATUS_SUCCESS) {
        return status;
      }
    }
  }

  if (rx_rings_ != nullptr) {
    for (UINT32 i = 0; i < rx_config_.array_size; i++) {
      if (!rx_rings_[i].is_init()) {
        continue;
      }

      status = admin_queue_.DestroyReceiveQueue(rx_rings_[i]);

      if (status != NDIS_STATUS_SUCCESS) {
        return status;
      }

      status = admin_queue_.UnregisterPageList(*rx_rings_[i].queue_page_list());

      if (status != NDIS_STATUS_SUCCESS) {
        return status;
      }
    }
  }

  return status;
}

void GvnicPciDevice::UpdateRxRssConfig() {
  if (rx_rings_ != nullptr) {
    for (UINT32 i = 0; i < rx_config_.array_size; i++) {
      rx_rings_[i].UpdateRssConfig(rss_config_);
    }
  }
}

// Setup the mapping between processor, traffic class to tx_ring index.
//
// If we have enough tx queues, which means tx_queue_size == tx_array_size,
// there will be one to one mapping between (slice, tc) => tx_ring.
//
// If tx_queue_size < tx_array_size, the mapping is setup as follows:
// 1. Fully populate the tc_0. If tx_queue_size < tx_max_slice, tx_ring will
// get reused in a round-robin style, i.e.,
// +------+------+------+------+------+------+------+------+------+
// |      |core_0|core_1|core_2|core_3|core_4|core_5|core_6|core_7|
// +------+------+------+------+------+------+------+------+------+
// | tc_0 | tx_0 | tx_1 | tx_2 | tx_0 | tx_1 | tx_2 | tx_0 | tx_1 |
// +------+------+------+------+------+------+------+------+------+
//
// 2. For all other tc, if it cannot find the dedicate tx_ring, it will reuse
// the ring from previous tc under the same core. i.e.,
//
// +------+------+------+------+------+------+------+------+------+
// |      |core_0|core_1|core_2|core_3|core_4|core_5|core_6|core_7|
// +------+------+------+------+------+------+------+------+------+
// | tc_0 | tx_0 | tx_1 | tx_2 | tx_3 | tx_4 | tx_5 | tx_6 | tx_7 |
// +------+------+------+------+------+------+------+------+------+
// | tc_1 | tx_8 | tx_9 | tx_2 | tx_3 | tx_4 | tx_5 | tx_6 | tx_7 |
// +------+------+------+------+------+------+------+------+------+
// |                              ....                            |
// +--------------------------------------------------------------+
// | tc_8 | tx_8 | tx_9 | tx_2 | tx_3 | tx_4 | tx_5 | tx_6 | tx_7 |
// +------+------+------+------+------+------+------+------+------+
void GvnicPciDevice::SetSliceTrafficClassToTxRingMapping() {
  NT_ASSERT(slice_tc_to_tx_ring_map_ != nullptr);

  // Step 1. Fully populate traffic_class_0.
  UINT32 valid_tx_ring_count = 0;
  UINT32 valid_tx_ring_pointer = 0;
  for (UINT32 i = 0; i < tx_config_.max_slices; i++) {
    if (tx_rings_[i].is_init()) {
      valid_tx_ring_count++;
    } else {
      if (valid_tx_ring_pointer == valid_tx_ring_count) {
        valid_tx_ring_pointer = 0;
      }
    }
    slice_tc_to_tx_ring_map_[i] = valid_tx_ring_pointer++;
  }

  // Step 2. Populate the rest of the traffic class.
  // Recall both tx_rings_ and slice_tc_to_tx_ring_map_ can be viewed as a 2d
  // array with max_traffic_class rows and max_clices column.
  for (UINT32 tc = 1; tc < tx_config_.max_traffic_class; tc++) {
    for (UINT32 slice = 0; slice < tx_config_.max_slices; slice++) {
      UINT32 array_idx = tc * tx_config_.max_slices + slice;
      if (tx_rings_[array_idx].is_init()) {
        slice_tc_to_tx_ring_map_[array_idx] = array_idx;
      } else {
        // Copy the tx_ring from previous tc with same slice.
        slice_tc_to_tx_ring_map_[array_idx] =
            slice_tc_to_tx_ring_map_[array_idx - tx_config_.max_slices];
      }
    }
  }

  DumpProcTrafficClassToTxRingMapping(slice_tc_to_tx_ring_map_,
                                      tx_config_.max_slices,
                                      tx_config_.max_traffic_class);
}

TxRing* GvnicPciDevice::GetTxRing(UINT32 slice, UINT32 traffic_class) {
  UINT32 array_idx = traffic_class * tx_config_.max_slices + slice;
  UINT32 ring_idx = slice_tc_to_tx_ring_map_[array_idx];
  return &tx_rings_[ring_idx];
}

void GvnicPciDevice::SetLinkState(NDIS_MEDIA_CONNECT_STATE new_state) {
  if (connect_state_ != new_state) {
    connect_state_ = new_state;

    NDIS_STATUS_INDICATION indication = {};
    NDIS_LINK_STATE state = {};

    state.Header.Revision = NDIS_LINK_STATE_REVISION_1;
    state.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    state.Header.Size = NDIS_SIZEOF_LINK_STATE_REVISION_1;
    state.MediaConnectState = connect_state_;
    state.MediaDuplexState = MediaDuplexStateFull;

    if (connect_state_ == MediaConnectStateConnected) {
      state.RcvLinkSpeed = state.XmitLinkSpeed = link_speed();
    } else {
      state.RcvLinkSpeed = state.XmitLinkSpeed = NDIS_LINK_SPEED_UNKNOWN;
    }
    state.PauseFunctions = NdisPauseFunctionsUnsupported;

    indication.Header.Type = NDIS_OBJECT_TYPE_STATUS_INDICATION;
    indication.Header.Revision = NDIS_STATUS_INDICATION_REVISION_1;
    indication.Header.Size = NDIS_SIZEOF_STATUS_INDICATION_REVISION_1;
    indication.SourceHandle = resources_->miniport_handle();
    indication.StatusCode = NDIS_STATUS_LINK_STATE;
    indication.StatusBuffer = &state;
    indication.StatusBufferSize = sizeof(state);
    DEBUGP(GVNIC_INFO, "[%s] Report link statues %d", __FUNCTION__,
           connect_state_);
    NdisMIndicateStatusEx(resources_->miniport_handle(), &indication);
  }
}

NDIS_STATUS GvnicPciDevice::UpdateOffloadConfig(
    NDIS_OFFLOAD_ENCAPSULATION encapsulation) {
  NDIS_STATUS status = UpdateOffloadConfigFromEncapsulation(
      hardware_offload_capabilities_, encapsulation,
      resources_->miniport_handle(), &offload_configuration_);
  LogOffloadSetting("Updated from Encapsualtion", offload_configuration_);

  if (status != NDIS_STATUS_SUCCESS) {
    return status;
  }

  bool rx_checksum_enabled =
      (offload_configuration_.Checksum.IPv4Receive.IpChecksum ==
       NDIS_OFFLOAD_SUPPORTED)
          ? true
          : false;
  UpdateRxChecksumSetting(rx_checksum_enabled);

  // Update packet header size.
  UpdateTxPacketHeaderLength(
      {encapsulation.IPv4.HeaderSize, encapsulation.IPv6.HeaderSize});

  return status;
}

// There could be multiple update request happening at the same time and logic
// needs to guarantee the last value always gets committed. So locker is
// required for the entire block.
void GvnicPciDevice::UpdateRxChecksumSetting(bool is_enabled) {
  SpinLockContext lock_context(&rx_checksum_enabled_spin_lock_,
                               /*is_dpc_level=*/false);
  // IP/TCP/UDP will have same setting. So just test Ip setting here.
  rx_checksum_enabled_ = is_enabled;
  if (rx_rings_ != nullptr) {
    for (UINT32 i = 0; i < rx_config_.array_size; i++) {
      rx_rings_[i].set_checksum_offload(rx_checksum_enabled_);
    }
  }

  DEBUGP(GVNIC_INFO, "[%s] Updated Rx checksum setting - enabled: %d",
         __FUNCTION__, rx_checksum_enabled_);
}

void GvnicPciDevice::UpdateTxPacketHeaderLength(
    EthHeaderLength eth_header_len) {
  SpinLockContext lock_context(&eth_header_len_spin_lock_,
                               /*is_dpc_level=*/false);
  eth_header_len_ = eth_header_len;
  if (tx_rings_ != nullptr) {
    for (UINT32 i = 0; i < tx_config_.array_size; i++) {
      tx_rings_[i].SetPacketHeaderLength(eth_header_len_);
    }
  }

  DEBUGP(GVNIC_INFO, "[%s] Updated header length: ipv4 - %#x, ipv6 - %#x",
         __FUNCTION__, eth_header_len_.IPv4, eth_header_len_.IPv6);
}

NDIS_STATUS GvnicPciDevice::UpdateOffloadConfig(
    NDIS_OFFLOAD_PARAMETERS offload_parameters) {
  NDIS_STATUS status = UpdateOffloadConfigFromOffloadParameters(
      hardware_offload_capabilities_, offload_parameters,
      resources_->miniport_handle(), &offload_configuration_);
  LogOffloadSetting("Updated from Offload Parameters", offload_configuration_);
  return status;
}

void GvnicPciDevice::set_packet_filter(UINT32 new_packet_filter) {
  DEBUGP(GVNIC_INFO, "[%s] Setting packet filter flags to %#lx", __FUNCTION__,
         new_packet_filter);
  packet_filter_ = new_packet_filter;
}

NDIS_STATUS GvnicPciDevice::UpdateRssParameters(
    const NDIS_RECEIVE_SCALE_PARAMETERS* rss_params, UINT32 param_length,
    UINT32* num_byte_read) {
  PAGED_CODE();

  RSSConfiguration new_rss_config = rss_config_;
  NDIS_STATUS status = new_rss_config.ApplyReceiveScaleParameters(
      rss_params, param_length, num_byte_read);
  if (status != NDIS_STATUS_SUCCESS) {
    return status;
  }

  DEBUGP(GVNIC_INFO, "[%s] Applying new rss settings:", __FUNCTION__);
  new_rss_config.DumpSettings();

  status = admin_queue_.SetRssParameters(new_rss_config);

  if (status == NDIS_STATUS_SUCCESS) {
    SpinLockContext lock_context(&rss_config_spin_lock_,
                                 /*is_dpc_level=*/false);
    DEBUGP(GVNIC_INFO, "[%s] rss setting updated.", __FUNCTION__);
    rss_config_ = new_rss_config;
    UpdateRxRssConfig();
  }

  DEBUGP(GVNIC_INFO, "[%s] Current rss setting:", __FUNCTION__);
  rss_config_.DumpSettings();

  return status;
}
