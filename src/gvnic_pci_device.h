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

#ifndef GVNIC_PCI_DEVICE_H_
#define GVNIC_PCI_DEVICE_H_

#include <ndis.h>

#include "adapter_configuration.h"  // NOLINT: include directory
#include "adapter_resource.h"       // NOLINT: include directory
#include "adapter_statistics.h"     // NOLINT: include directory
#include "admin_queue.h"            // NOLINT: include directory
#include "device_parameters.h"      // NOLINT: include directory
#include "netutils.h"               // NOLINT: include directory
#include "notify_manager.h"         // NOLINT: include directory
#include "offload.h"                // NOLINT: include directory
#include "queue_page_list.h"        // NOLINT: include directory
#include "rss_configuration.h"      // NOLINT: include directory
#include "rx_ring.h"                // NOLINT: include directory
#include "shared_memory.h"          // NOLINT: include directory
#include "tx_ring_dma.h"            // NOLINT: include directory
#include "tx_ring_qpl.h"            // NOLINT: include directory

constexpr ULONGLONG kOneHundredGigabit = 100ull * 1000 * 1000 * 1000;

// Class for device property and operations.
class GvnicPciDevice final {
 public:
  GvnicPciDevice()
      : resources_(nullptr),
        device_params_(),
        ignore_flow_table_(false),
        allow_raw_addressing_from_registry_(false),
        slice_tc_to_tx_ring_map_(nullptr),
        tx_rings_(nullptr),
        tx_queue_page_lists_(nullptr),
        rx_rings_(nullptr),
        rx_queue_page_lists_(nullptr),
        queue_interrupts_enabled_(false),
        connect_state_(MediaConnectStateDisconnected),
        packet_filter_(0),
        rx_checksum_enabled_(false),
        stop_reason_(0) {}
  ~GvnicPciDevice();

  // Not copyable or movable
  GvnicPciDevice(const GvnicPciDevice&) = delete;
  GvnicPciDevice& operator=(const GvnicPciDevice&) = delete;

  // Initialize device object with resource and configurations.
  NDIS_STATUS Init(AdapterResources* resources, AdapterStatistics* statistics,
                   const AdapterConfiguration& configuration);

  // Reset device back to init state.
  void Reset(AdapterResources* resources, AdapterStatistics* statistics,
             const AdapterConfiguration& configuration);

  // Release allocated resource including:
  // - AdminQueue.
  // - Counter array.
  // - Notify blocks.
  // - transmit rings.
  // - receive rings.
  void Release();

  void SendNetBufferLists(PNET_BUFFER_LIST net_buffer_list, bool dpc_level);

  // Unregister/Deallocate tx/rx rings.
  // Report connect state MediaConnectStateDisconnected if succeed.
  NDIS_STATUS Pause();

  // Allocate and register tx/rx rings.
  // Report connect state MediaConnectStateConnected if succeed.
  NDIS_STATUS Restart();

  void SurpriseRemove();
  void HandleManagementQueueRequest();

  const QueueConfig& transmit_queue_config() const { return tx_config_; }
  const QueueConfig& receive_queue_config() const { return rx_config_; }
  bool is_media_connected() const { return true; }
  bool is_priority_supported() const { return false; }
  bool is_vlan_supported() const { return false; }
  const MaxPacketSize& max_packet_size() const { return max_packet_size_; }
  ULONGLONG link_speed() const { return kOneHundredGigabit; }
  const UCHAR* current_mac_address() const { return current_mac_; }
  const UCHAR* permanent_mac_address() const { return permanent_mac_; }
  const NotifyManager* notify_manager() const { return &notify_manager_; }
  // We cannot use num_queues directly, as queues may be distributed across
  // multiple rx groups. Instead we use the number of slices with queues
  // assigned. Queues are assigned to group0 until group0 is filled, and then to
  // group1, etc.
  UINT32 num_rss_queue() const {
    return min(rx_config_.num_queues, rx_config_.num_slices);
  }
  UINT32 packet_filter() const { return packet_filter_; }
  bool use_raw_addressing() const {
    return device_params_.support_raw_addressing &&
           allow_raw_addressing_from_registry_;
  }
  // Update the current packet filter flags for this device.
  void set_packet_filter(UINT32 new_packet_filter);
  NDIS_OFFLOAD hardware_offload_capabilities() const {
    return hardware_offload_capabilities_;
  }
  NDIS_OFFLOAD offload_configuration() const { return offload_configuration_; }
  bool rsc_ipv4_enabled() const {
#ifdef SUPPORT_RSC
    return !!offload_configuration_.Rsc.IPv4.Enabled;
#else
    return false;
#endif
  }
  bool QueueInterruptsEnabled() const { return queue_interrupts_enabled_; }

  // Update offload config based on NDIS_OFFLOAD_ENCAPSULATION.
  // Return NDIS_STATUS_INVALID_PARAMETER if the request is not valid.
  // Return NDIS_STATUS_SUCCESS if succeed.
  NDIS_STATUS UpdateOffloadConfig(NDIS_OFFLOAD_ENCAPSULATION encapsulation);

  // Update offload config based on NDIS_OFFLOAD_PARAMETERS.
  // Return NDIS_STATUS_INVALID_PARAMETER if the request is not valid.
  // Return NDIS_STATUS_SUCCESS if succeed.
  NDIS_STATUS UpdateOffloadConfig(NDIS_OFFLOAD_PARAMETERS offload_parameters);

  // Update RSS configuration based on NDIS_RECEIVE_SCALE_PARAMETERS.
  // Need to take a pointer since pointer offset calculation is needed.
  NDIS_STATUS UpdateRssParameters(
      const NDIS_RECEIVE_SCALE_PARAMETERS* rss_params, UINT32 param_length,
      UINT32* num_byte_read);

  // Called before the framework calls GvnicRestart when entering D0.
  // Reinitializes the admin queue with the existing settings.
  NDIS_STATUS BeginTransitionToFullPowerState();

  // Called after the framework calls GvnicPause when leaving D0. Deconfigures
  // and releases the admin queue.
  NDIS_STATUS FinishTransitionToLowPowerState();

 private:
  // Load registry configurations.
  NDIS_STATUS LoadAdapterConfiguration(
      const AdapterConfiguration& configuration);

  // Load device initial configurations.
  NDIS_STATUS LoadDeviceConfiguration();

  // Allocate required resource for device and register it with device.
  NDIS_STATUS ConfigureDeviceResource();

  // Validates and sets basic tx/rx queue configurations. This writes to the
  // system I/O error log file if the queue config is invalid.
  NDIS_STATUS SetTransmitQueueConfig();

  // Set driver version to device.
  void SetDriverInfo();

  // Allocate Memory required to hold all tx/rx rings.
  NDIS_STATUS AllocateRings();

  // Init full list of rx ring.
  bool InitRxRings();

  // Init full list of tx ring.
  bool InitTxRings();

  // Free resources in the allocated rings.
  void FreeRings();

  // Call admin queue abi to register rings with device.
  NDIS_STATUS RegisterRings();

  // Call admin queue abi to unregister tx/rx rings with the device.
  NDIS_STATUS UnregisterRings();

  // Update rx rings with rss config settings.
  void UpdateRxRssConfig();

  // Update all rx rings with checksum setting.
  void UpdateRxChecksumSetting(bool enabled);

  // Update all tx rings with updated header length.
  void UpdateTxPacketHeaderLength(EthHeaderLength eth_header_len);

  // Save new_state to connect_state_. Report the new state to NDIS if changed.
  void SetLinkState(NDIS_MEDIA_CONNECT_STATE new_state);

  // Setup mapping between processor, traffic class to tx ring index.
  void SetSliceTrafficClassToTxRingMapping();

  // Get tx ring index for handling request based on slice and traffic_class.
  TxRing* GetTxRing(UINT32 slice, UINT32 traffic_class);

  // Allows enabling and disabling the queue interrupts. This is done in
  // addition to masking the interrupts when the interrupt would touch
  // invalid memory.
  void DisableQueueInterrupts();
  void EnableQueueInterrupts();

  // Prepares each ring to be released. Rx rings will stop processing packets
  // asynchronously, and Tx rings will stop accepting traffic and begin to
  // drain.
  void PrepareRingsForRelease();

  // Rings can be detached from the device before this, but rx rings must not
  // be freed until all net buffer lists handled asynchronously have been
  // completed.
  bool IsSafeToReleaseRings() const;

  AdapterResources* resources_;
  AdapterStatistics* statistics_;

  AdminQueue admin_queue_;

  // Device settings.
  GvnicDeviceParameters device_params_;
  MaxPacketSize max_packet_size_;
  UCHAR permanent_mac_[kEthAddrLen];
  UCHAR current_mac_[kEthAddrLen];
  // Whether device needs the driver to ignore the flow table and route all
  // traffic into Traffic Class 0.
  bool ignore_flow_table_;

  // Whether raw addressing is allowed via the registry. By default raw
  // addressing is allowed, but the device must also report it as enabled for
  // it to be used.
  bool allow_raw_addressing_from_registry_;

  // Array for storing counters of the total number of package processed by NIC.
  // Based on device contact, it is an array of UINT32 and the length is based
  // on device_params_.descriptor.event_counters.
  SharedMemory<DeviceCounter> counter_array_;

  NotifyManager notify_manager_;

  // Map between processor index(slice), traffic_class to tx ring index.
  UINT32* slice_tc_to_tx_ring_map_;

  QueueConfig tx_config_;
  TxRing** tx_rings_;                   // Size of tx_config_.array_size
  QueuePageList* tx_queue_page_lists_;  // Size of tx_config_.max_queues

  QueueConfig rx_config_;
  RxRing* rx_rings_;                    // Size of rx_config_.array_size
  QueuePageList* rx_queue_page_lists_;  // Size of rx_config_.max_queues

  NDIS_OFFLOAD hardware_offload_capabilities_;
  NDIS_OFFLOAD offload_configuration_;

  bool queue_interrupts_enabled_;

  NDIS_MEDIA_CONNECT_STATE connect_state_;

  // Set of flags indicating filters
  UINT32 packet_filter_;

  NDIS_SPIN_LOCK eth_header_len_spin_lock_;
  EthHeaderLength eth_header_len_;

  NDIS_SPIN_LOCK rx_checksum_enabled_spin_lock_;
  bool rx_checksum_enabled_;

  NDIS_SPIN_LOCK rss_config_spin_lock_;
  RSSConfiguration rss_config_;

  NDIS_STATUS stop_reason_;
};

#endif  // GVNIC_PCI_DEVICE_H_
