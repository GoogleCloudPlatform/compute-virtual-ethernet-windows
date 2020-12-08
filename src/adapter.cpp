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

#include "adapter.h"  // NOLINT: include directory

#include <ndis.h>

#include "adapter_resource.h"  // NOLINT: include directory
#include "netutils.h"          // NOLINT: include directory
#include "offload.h"           // NOLINT: include directory
#include "oid.h"               // NOLINT: include directory
#include "rss_configuration.h"  // NOLINT: include directory
#include "rx_ring.h"           // NOLINT: include directory
#include "trace.h"             // NOLINT: include directory
#include "utils.h"             // NOLINT: include directory

#include "adapter.tmh"  // NOLINT: trace message header

extern NDIS_HANDLE DriverHandle;

namespace {
constexpr int kGvnicMulticastListSize = 1;

// Free resource allocated inside AdapterContext.
inline void GvnicFreeMemory(AdapterContext* context) {
  PAGED_CODE();

  // Interrupts can happen during this callback until this function returns.
  context->resources.DeregisterInterrupts();

  // NdisFreeMemory doesn't call destructor. Call destructor explicitly will
  // make the compiler call delete operator. To make it clear that the code
  // is just trying to release allocated resources not memory, call Release() to
  // cleanup here.
  context->device.Release();
  context->statistics.Release();
  context->resources.Release();

  NdisFreeMemory(context, 0, 0);
}

#if NDIS_SUPPORT_NDIS620
// Initialize NDIS_PM_CAPABILITIES required by NDIS620+.
void InitNdisPMCapabilities(PNDIS_PM_CAPABILITIES pndis_pm_capabilities) {
  PAGED_CODE();
  NdisZeroMemory(pndis_pm_capabilities, sizeof(*pndis_pm_capabilities));
  pndis_pm_capabilities->Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
#if NDIS_SUPPORT_NDIS630
  pndis_pm_capabilities->Header.Revision = NDIS_PM_CAPABILITIES_REVISION_2;
  pndis_pm_capabilities->Header.Size =
      NDIS_SIZEOF_NDIS_PM_CAPABILITIES_REVISION_2;
#else
  pndis_pm_capabilities->Header.Revision = NDIS_PM_CAPABILITIES_REVISION_1;
  pndis_pm_capabilities->Header.Size =
      NDIS_SIZEOF_NDIS_PM_CAPABILITIES_REVISION_1;
#endif  // NDIS_SUPPORT_NDIS630

  // No wake-on-LAN (WOL) support
  pndis_pm_capabilities->SupportedWoLPacketPatterns = 0;
  pndis_pm_capabilities->NumTotalWoLPatterns = 0;
  pndis_pm_capabilities->MaxWoLPatternSize = 0;
  pndis_pm_capabilities->MaxWoLPatternOffset = 0;
  pndis_pm_capabilities->MaxWoLPacketSaveBuffer = 0;

  // no low power protocol offload support (ARP, NS IPv6)
  pndis_pm_capabilities->SupportedProtocolOffloads = 0;
  pndis_pm_capabilities->NumArpOffloadIPv4Addresses = 0;
  pndis_pm_capabilities->NumNSOffloadIPv6Addresses = 0;

  // No support on magic packet
  pndis_pm_capabilities->MinMagicPacketWakeUp = NdisDeviceStateUnspecified;

  // No support for wake on link change supported
  pndis_pm_capabilities->MinLinkChangeWakeUp = NdisDeviceStateUnspecified;

  // No support for on pattern supported
  pndis_pm_capabilities->MinPatternWakeUp = NdisDeviceStateUnspecified;
}
#else
// Initialize NDIS_PNP_CAPABILITIES required by NDIS.
void InitPNPCapabilities(PNDIS_PNP_CAPABILITIES pndis_pnp_capabilities) {
  PAGED_CODE();
  NdisZeroMemory(pndis_pnp_capabilities, sizeof(*pndis_pnp_capabilities));
  // No wake up support.
  pndis_pnp_capabilities->WakeUpCapabilities.MinMagicPacketWakeUp =
      NdisDeviceStateUnspecified;
  pndis_pnp_capabilities->WakeUpCapabilities.MinPatternWakeUp =
      NdisDeviceStateUnspecified;
  pndis_pnp_capabilities->WakeUpCapabilities.MinLinkChangeWakeUp =
      NdisDeviceStateUnspecified;
}
#endif  // NDIS_SUPPORT_NDIS620

// Initialize required adapter registration attributes.
NDIS_STATUS InitAdapterRegistrationAttributes(
    NDIS_HANDLE miniport_adapter_handle, AdapterContext* adapt_context) {
  PAGED_CODE();
  NDIS_MINIPORT_ADAPTER_ATTRIBUTES miniport_attrs = {};

  miniport_attrs.RegistrationAttributes.Header.Type =
      NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES;
#if NDIS_SUPPORT_NDIS630
  miniport_attrs.RegistrationAttributes.Header.Revision =
      NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_2;
  miniport_attrs.RegistrationAttributes.Header.Size =
      NDIS_SIZEOF_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_2;
#else
  miniport_attrs.RegistrationAttributes.Header.Revision =
      NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_1;
  miniport_attrs.RegistrationAttributes.Header.Size =
      NDIS_SIZEOF_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_1;
#endif  // NDIS_SUPPORT_NDIS630

  miniport_attrs.RegistrationAttributes.MiniportAdapterContext = adapt_context;
  miniport_attrs.RegistrationAttributes.AttributeFlags =
      NDIS_MINIPORT_ATTRIBUTES_HARDWARE_DEVICE |
      NDIS_MINIPORT_ATTRIBUTES_BUS_MASTER |
      NDIS_MINIPORT_ATTRIBUTES_NO_HALT_ON_SUSPEND;  // Standard NIC flags.

  miniport_attrs.RegistrationAttributes.CheckForHangTimeInSeconds = 4;
  miniport_attrs.RegistrationAttributes.InterfaceType = NdisInterfacePci;
  return NdisMSetMiniportAttributes(miniport_adapter_handle, &miniport_attrs);
}

// Initialize required adapter general attributes.
NDIS_STATUS InitAdapterGeneralAttributes(NDIS_HANDLE miniport_adapter_handle,
                                         AdapterContext* adapter_context) {
  PAGED_CODE();
  NDIS_MINIPORT_ADAPTER_ATTRIBUTES miniport_attrs = {};

  miniport_attrs.GeneralAttributes.Header.Type =
      NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES;
#if NDIS_SUPPORT_NDIS620
  miniport_attrs.GeneralAttributes.Header.Revision =
      NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES_REVISION_2;
  miniport_attrs.GeneralAttributes.Header.Size =
      NDIS_SIZEOF_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES_REVISION_2;
  NDIS_PM_CAPABILITIES pm_capacity;
  InitNdisPMCapabilities(&pm_capacity);
  miniport_attrs.GeneralAttributes.PowerManagementCapabilitiesEx = &pm_capacity;
#else
  miniport_attrs.GeneralAttributes.Header.Revision =
      NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES_REVISION_1;
  miniport_attrs.GeneralAttributes.Header.Size =
      NDIS_SIZEOF_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES_REVISION_1;
  NDIS_PNP_CAPABILITIES pnp_capacity;
  InitPNPCapabilities(&pnp_capacity);
  miniport_attrs.GeneralAttributes.PowerManagementCapabilities = &pnp_capacity;
#endif  // NDIS_SUPPORT_NDIS620

  // Ethernet (802.3) network.
  miniport_attrs.GeneralAttributes.MediaType = NdisMedium802_3;
  // The Ethernet (802.3) physical medium.
  miniport_attrs.GeneralAttributes.PhysicalMediumType = NdisPhysicalMedium802_3;
  miniport_attrs.GeneralAttributes.MtuSize =
      adapter_context->device.max_packet_size().max_data_size;
  miniport_attrs.GeneralAttributes.MaxXmitLinkSpeed =
      miniport_attrs.GeneralAttributes.MaxRcvLinkSpeed =
          adapter_context->device.link_speed();
  miniport_attrs.GeneralAttributes.XmitLinkSpeed =
      miniport_attrs.GeneralAttributes.RcvLinkSpeed =
          adapter_context->device.is_media_connected()
              ? adapter_context->device.link_speed()
              : NDIS_LINK_SPEED_UNKNOWN;
  miniport_attrs.GeneralAttributes.MediaConnectState =
      adapter_context->device.is_media_connected()
          ? MediaConnectStateConnected
          : MediaConnectStateDisconnected;

  // The miniport adapter can transmit and receive simultaneously.
  miniport_attrs.GeneralAttributes.MediaDuplexState = MediaDuplexStateFull;
  miniport_attrs.GeneralAttributes.LookaheadSize =
      adapter_context->device.max_packet_size().max_full_size;
  miniport_attrs.GeneralAttributes.MacOptions =
      // The protocol driver is free to access indicated data by any means.
      NDIS_MAC_OPTION_COPY_LOOKAHEAD_DATA |
      // Must be set since using  NdisMIndicateReceivePacket.
      NDIS_MAC_OPTION_TRANSFERS_NOT_PEND |
      // NIC has no internal loopback support.
      NDIS_MAC_OPTION_NO_LOOPBACK |
      // Allow mac overwritten.
      NDIS_MAC_OPTION_SUPPORTS_MAC_ADDRESS_OVERWRITE;
  if (adapter_context->device.is_priority_supported())
    miniport_attrs.GeneralAttributes.MacOptions |=
        NDIS_MAC_OPTION_8021P_PRIORITY;
  if (adapter_context->device.is_vlan_supported())
    miniport_attrs.GeneralAttributes.MacOptions |= NDIS_MAC_OPTION_8021Q_VLAN;
  miniport_attrs.GeneralAttributes.SupportedPacketFilters =
      // All required for native 802.11 Packet Filters.
      NDIS_PACKET_TYPE_DIRECTED | NDIS_PACKET_TYPE_MULTICAST |
      NDIS_PACKET_TYPE_BROADCAST | NDIS_PACKET_TYPE_PROMISCUOUS |
      NDIS_PACKET_TYPE_ALL_MULTICAST;
  miniport_attrs.GeneralAttributes.MaxMulticastListSize =
      kGvnicMulticastListSize;
  miniport_attrs.GeneralAttributes.MacAddressLength = kEthAddrLen;

  // RSS support.
  IO_INTERRUPT_MESSAGE_INFO* msi_table =
      adapter_context->resources.msi_info_table();
  NDIS_RECEIVE_SCALE_CAPABILITIES rss_capabilities =
      RSSConfiguration::GetCapabilities(
          msi_table->MessageCount, adapter_context->device.num_rss_queue());
  miniport_attrs.GeneralAttributes.RecvScaleCapabilities = &rss_capabilities;
  // Provides native support for multicast or broadcast services.
  miniport_attrs.GeneralAttributes.AccessType = NET_IF_ACCESS_BROADCAST;
  // Can send and receive data.
  miniport_attrs.GeneralAttributes.DirectionType = NET_IF_DIRECTION_SENDRECEIVE;
  // Ethernet connection is dedicated.
  miniport_attrs.GeneralAttributes.ConnectionType = NET_IF_CONNECTION_DEDICATED;
  // Value for any Ethernet-like interface.
  miniport_attrs.GeneralAttributes.IfType = IF_TYPE_ETHERNET_CSMACD;
  // True for physical adapter.
  miniport_attrs.GeneralAttributes.IfConnectorPresent = TRUE;

  ETH_COPY_NETWORK_ADDRESS(miniport_attrs.GeneralAttributes.PermanentMacAddress,
                           adapter_context->device.permanent_mac_address());
  ETH_COPY_NETWORK_ADDRESS(miniport_attrs.GeneralAttributes.CurrentMacAddress,
                           adapter_context->device.current_mac_address());

  miniport_attrs.GeneralAttributes.SupportedOidList =
      const_cast<NDIS_OID*>(kSupportedOids);
  miniport_attrs.GeneralAttributes.SupportedOidListLength =
      sizeof(kSupportedOids);
  adapter_context->statistics.Init();
  miniport_attrs.GeneralAttributes.SupportedStatistics =
      adapter_context->statistics.supported_statistics();

  return NdisMSetMiniportAttributes(miniport_adapter_handle, &miniport_attrs);
}

NDIS_STATUS InitAdapterOffsetAttributes(NDIS_HANDLE miniport_adapter_handle,
                                        AdapterContext* adapter_context) {
  PAGED_CODE();
  NDIS_MINIPORT_ADAPTER_ATTRIBUTES miniport_attrs = {};
  NDIS_MINIPORT_ADAPTER_OFFLOAD_ATTRIBUTES* offload_attrs =
      &miniport_attrs.OffloadAttributes;
  offload_attrs->Header.Type =
      NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_OFFLOAD_ATTRIBUTES;
  offload_attrs->Header.Revision =
      NDIS_MINIPORT_ADAPTER_OFFLOAD_ATTRIBUTES_REVISION_1;
  offload_attrs->Header.Size =
      NDIS_SIZEOF_MINIPORT_ADAPTER_OFFLOAD_ATTRIBUTES_REVISION_1;

  NDIS_OFFLOAD hardware_capabilities =
      adapter_context->device.hardware_offload_capabilities();
  NDIS_OFFLOAD offload_config = adapter_context->device.offload_configuration();
  offload_attrs->DefaultOffloadConfiguration = &offload_config;
  offload_attrs->HardwareOffloadCapabilities = &hardware_capabilities;

  LogOffloadSetting("DefaultOffloadConfiguration",
                    *offload_attrs->DefaultOffloadConfiguration);
  LogOffloadSetting("HardwareOffloadCapabilities",
                    *offload_attrs->HardwareOffloadCapabilities);

  return NdisMSetMiniportAttributes(miniport_adapter_handle, &miniport_attrs);
}

NDIS_STATUS InitializeAdapterContext(
    AdapterContext* adapter_context, NDIS_HANDLE miniport_adapter_handle,
    PNDIS_MINIPORT_INIT_PARAMETERS miniport_init_parameters) {
  NDIS_STATUS status = InitAdapterRegistrationAttributes(
      miniport_adapter_handle, adapter_context);
  if (status != NDIS_STATUS_SUCCESS) {
    DEBUGP(GVNIC_ERROR,
           "[%s] ERROR: NdisMSetMiniportAttributes for RegistrationAttributes"
           " failed (%X)!\n",
           __FUNCTION__, status);
    return status;
  }

  // Read registry configurations.
  adapter_context->configuration.Initialize(miniport_adapter_handle);

  // Initialize resources.
  status = adapter_context->resources.Initialize(
      DriverHandle, miniport_adapter_handle,
      miniport_init_parameters->AllocatedResources, adapter_context);
  if (status != NDIS_STATUS_SUCCESS) {
    DEBUGP(GVNIC_ERROR, "[%s] ERROR: Failed to initialize resources (%X)!\n",
           __FUNCTION__, status);
    return status;
  }

  // Initialize device object.
  status = adapter_context->device.Init(&adapter_context->resources,
                                        &adapter_context->statistics,
                                        adapter_context->configuration);
  if (status != NDIS_STATUS_SUCCESS) {
    DEBUGP(GVNIC_ERROR, "[%s] ERROR: Failed to initialize device (%X)!\n",
           __FUNCTION__, status);
    return status;
  }

  // Set Adapter GeneralAttributes.
  status =
      InitAdapterGeneralAttributes(miniport_adapter_handle, adapter_context);
  if (status != NDIS_STATUS_SUCCESS) {
    DEBUGP(GVNIC_ERROR,
           "[%s] ERROR: NdisMSetMiniportAttributes for GeneralAttributes "
           "failed (%#X)!",
           __FUNCTION__, status);
    return status;
  }

  // Set Adapter offload attributes.
  status =
      InitAdapterOffsetAttributes(miniport_adapter_handle, adapter_context);
  if (status != NDIS_STATUS_SUCCESS) {
    DEBUGP(GVNIC_ERROR,
           "[%s] ERROR: NdisMSetMiniportAttributes for OffloadAttributes"
           "failed (%#X)!",
           __FUNCTION__, status);
    return status;
  }

  return NDIS_STATUS_SUCCESS;
}

// Set target processor for msi vectors.
// Return the total number of msi count.
UINT GetMsiVectorCount(const IO_RESOURCE_REQUIREMENTS_LIST& resource_list) {
  UINT msi_count = 0;

  const IO_RESOURCE_LIST* io_resource_list = resource_list.List;

  for (UINT i = 0; i < resource_list.AlternativeLists; ++i) {
    for (UINT j = 0; j < io_resource_list->Count; ++j) {
      const IO_RESOURCE_DESCRIPTOR& desc = io_resource_list->Descriptors[j];
      if (desc.Type == CmResourceTypeInterrupt &&
          (desc.Flags & CM_RESOURCE_INTERRUPT_MESSAGE) &&
          (desc.Flags & CM_RESOURCE_INTERRUPT_POLICY_INCLUDED)) {
        msi_count++;
      }
    }

    // Advance to the next IP_RESOURCES_LIST block in memory.
    io_resource_list = reinterpret_cast<const IO_RESOURCE_LIST*>(
        io_resource_list->Descriptors + io_resource_list->Count);
  }

  DEBUGP(GVNIC_INFO, "[%s] Found %u msi vectors.", __FUNCTION__, msi_count);

  return msi_count;
}

// Helper function for getting the TargetedProcessors for an rx slice.
KAFFINITY GetTargetedProcessorsForRx(
    UINT num_rx_configured, UINT rx_scale_factor,
    PNDIS_RSS_PROCESSOR_INFO rss_processor_info) {
  if (rss_processor_info == nullptr ||
      num_rx_configured >= rss_processor_info->RssProcessorCount) {
    return 1ull << (num_rx_configured * rx_scale_factor);
  } else {
    PUCHAR first_proc = reinterpret_cast<PUCHAR>(rss_processor_info) +
                        rss_processor_info->RssProcessorArrayOffset;
    PNDIS_RSS_PROCESSOR processor = reinterpret_cast<PNDIS_RSS_PROCESSOR>(
        first_proc +
        num_rx_configured * rss_processor_info->RssProcessorEntrySize);
    return 1ull << processor->ProcNum.Number;
  }
}

IO_RESOURCE_REQUIREMENTS_LIST* RequestAdditionalMsiResourcesForRss(
    IO_RESOURCE_REQUIREMENTS_LIST* old_requirements_list,
    NDIS_RSS_PROCESSOR_INFO* rss_processor_info, UINT num_rx, UINT num_tx,
    NDIS_HANDLE device_handle) {
  const ULONG additional_entries =
      rss_processor_info->RssProcessorCount - num_rx;
  const ULONG additional_size_required =
      sizeof(IO_RESOURCE_DESCRIPTOR) * additional_entries;
  const ULONG size_of_new_list =
      old_requirements_list->ListSize + additional_size_required;
  IO_RESOURCE_REQUIREMENTS_LIST* new_requirements_list =
      static_cast<IO_RESOURCE_REQUIREMENTS_LIST*>(
          NdisAllocateMemoryWithTagPriority(device_handle, size_of_new_list,
                                            kGvnicMemoryTag,
                                            NormalPoolPriority));
  if (new_requirements_list == nullptr) {
    return nullptr;
  } else {
    NdisZeroMemory(new_requirements_list, size_of_new_list);
  }

  // We want to insert our new entries directly after the existing entries.
  // There is an additional entry we earlier reserved for driver management.
  ULONG expected_msi_entries = num_rx + num_tx + 1;
  ULONG seen_msi_entries = 0;
  bool added_additional_entries = false;

  // The resource requirement list has the form shown below. We have allocated
  // additional memory for new MSI-X entries which should come immediately
  // after the existing MSI-X entries within the same resource list.
  //
  // IO_RESOURCE_REQUIREMENTS_LIST
  //   IO_RESOURCE_LIST[0]
  //     IO_RESOURCE_DESCRIPTOR[0]
  //     ...
  //     IO_RESOURCE_DESCRIPTOR[Count - 1]
  //   IO_RESOURCE_LIST[1]
  //     IO_RESOURCE_DESCRIPTOR[0]
  //     ...
  //     IO_RESOURCE_DESCRIPTOR[Count - 1]
  //   ...
  //   IO_RESOURCE_LIST[AlternativeLists - 1]
  NdisMoveMemory(new_requirements_list, old_requirements_list,
                 sizeof(IO_RESOURCE_REQUIREMENTS_LIST));
  new_requirements_list->ListSize = size_of_new_list;

  IO_RESOURCE_LIST* new_resource_list = new_requirements_list->List;
  IO_RESOURCE_LIST* old_resource_list = old_requirements_list->List;
  for (UINT i = 0; i < new_requirements_list->AlternativeLists; i++) {
    NdisMoveMemory(new_resource_list, old_resource_list,
                   sizeof(IO_RESOURCE_LIST));
    for (UINT old_desc_index = 0, new_desc_index = 0;
         old_desc_index < old_resource_list->Count;
         old_desc_index++, new_desc_index++) {
      IO_RESOURCE_DESCRIPTOR* old_desc =
          &old_resource_list->Descriptors[old_desc_index];
      IO_RESOURCE_DESCRIPTOR* new_desc =
          &new_resource_list->Descriptors[new_desc_index];
      NdisMoveMemory(new_desc, old_desc, sizeof(IO_RESOURCE_DESCRIPTOR));
      if (new_desc->Type == CmResourceTypeInterrupt &&
          (new_desc->Flags & CM_RESOURCE_INTERRUPT_MESSAGE) &&
          (new_desc->Flags & CM_RESOURCE_INTERRUPT_POLICY_INCLUDED)) {
        seen_msi_entries++;
      }

      if (added_additional_entries == false &&
          seen_msi_entries == expected_msi_entries) {
        added_additional_entries = true;
        UINT curr_rss_proc_index = num_rx;

        while (new_desc_index < old_desc_index + additional_entries) {
          new_desc_index++;
          IO_RESOURCE_DESCRIPTOR* additional_desc =
              &new_resource_list->Descriptors[new_desc_index];
          additional_desc->Type = CmResourceTypeInterrupt;
          additional_desc->ShareDisposition = CmResourceShareDeviceExclusive;
          additional_desc->Flags = CM_RESOURCE_INTERRUPT_LATCHED |
                                   CM_RESOURCE_INTERRUPT_MESSAGE |
                                   CM_RESOURCE_INTERRUPT_POLICY_INCLUDED;

          // Both minimum and maximum are set to the same value for MSI-X
          // interrupts.
          additional_desc->u.Interrupt.MinimumVector =
              CM_RESOURCE_INTERRUPT_MESSAGE_TOKEN;
          additional_desc->u.Interrupt.MaximumVector =
              CM_RESOURCE_INTERRUPT_MESSAGE_TOKEN;

          additional_desc->u.Interrupt.AffinityPolicy =
              IrqPolicySpecifiedProcessors;

          PUCHAR first_proc = reinterpret_cast<PUCHAR>(rss_processor_info) +
                              rss_processor_info->RssProcessorArrayOffset;
          PNDIS_RSS_PROCESSOR processor = reinterpret_cast<PNDIS_RSS_PROCESSOR>(
              first_proc +
              curr_rss_proc_index * rss_processor_info->RssProcessorEntrySize);
          additional_desc->u.Interrupt.TargetedProcessors =
              (1ull << processor->ProcNum.Number);
          new_resource_list->Count++;

          curr_rss_proc_index++;
        }
      }
    }

    // Advance to the next IO_RESOURCES_LIST block in memory.
    old_resource_list = reinterpret_cast<IO_RESOURCE_LIST*>(
        old_resource_list->Descriptors + old_resource_list->Count);
    new_resource_list = reinterpret_cast<IO_RESOURCE_LIST*>(
        new_resource_list->Descriptors + new_resource_list->Count);
  }

  return new_requirements_list;
}

// Set target processor for msi vectors.
//
// Arguments:
//  num_tx: number of tx queue.
//  num_rx: number of rx queue.
//  rx_scale_factor: the internal between two interrupt target processor.
//  rss_processor_info: system information about rss processors.
//  resource_list: resource list contain msi vectors.
void SetMsiAffinity(UINT num_tx, UINT num_rx, UINT rx_scale_factor,
                    PNDIS_RSS_PROCESSOR_INFO rss_processor_info,
                    IO_RESOURCE_REQUIREMENTS_LIST* resource_list) {
  UINT num_tx_configured = 0;
  UINT num_rx_configured = 0;

  // The following logic tries to optimize for the most common scenario:
  //  - num_rx == number_processor / 2
  //  - RSS is turned on
  //
  // The preference will be to follow system provided RSS CPU information. If
  // there is no provided RSS CPU information, or we have more rx queues than
  // RSS CPUs, we fall back to the default logic of spreading rx queues across
  // every second vCPU to avoid hyerpthreading CPUs.
  // +--------+--------+--------+--------+-----+
  // | vCPU_1 | vCPU_2 | vCPU_3 | vCPU_4 | ... |
  // | rx_0   | X      | rx_1   | X      | ... |
  // +--------+--------+--------+--------+-----+
  IO_RESOURCE_LIST* io_resource_list = resource_list->List;

  for (UINT i = 0; i < resource_list->AlternativeLists; ++i) {
    for (UINT j = 0; j < io_resource_list->Count; ++j) {
      IO_RESOURCE_DESCRIPTOR* desc = &io_resource_list->Descriptors[j];
      if (desc->Type == CmResourceTypeInterrupt &&
          (desc->Flags & CM_RESOURCE_INTERRUPT_MESSAGE) &&
          (desc->Flags & CM_RESOURCE_INTERRUPT_POLICY_INCLUDED)) {
        if (num_tx_configured < num_tx) {
          desc->u.Interrupt.AffinityPolicy = IrqPolicySpecifiedProcessors;
          desc->u.Interrupt.TargetedProcessors = (1ull << num_tx_configured);
          num_tx_configured++;
        } else if (num_rx_configured < num_rx) {
          desc->u.Interrupt.AffinityPolicy = IrqPolicySpecifiedProcessors;
          desc->u.Interrupt.TargetedProcessors = GetTargetedProcessorsForRx(
              num_rx_configured, rx_scale_factor, rss_processor_info);
          num_rx_configured++;
        }
      }
    }

    // Advance to the next IP_RESOURCES_LIST block in memory.
    io_resource_list = reinterpret_cast<IO_RESOURCE_LIST*>(
        io_resource_list->Descriptors + io_resource_list->Count);
  }

  // Verify all tx/rx has been configured.
  NT_ASSERT(num_tx_configured == num_tx);
  NT_ASSERT(num_rx_configured == num_rx);

  DEBUGP(GVNIC_INFO,
         "[%s] Get request to config %u tx and %u rx queue. Configured %u tx "
         "queue and %u rx queue.",
         __FUNCTION__, num_tx, num_rx, num_tx_configured, num_rx_configured);
}

}  // namespace

// Called by NDIS to initialize a miniport adapter for network I/O operations.
//
// Arguments:
//   miniport_adapter_handle - An NDIS-supplied handle that identifies the
//    miniport adapter that the miniport driver should initialize.
//   miniport_driver_context - A handle to a driver-allocated context area where
//    the driver maintains state and configuration information.
//   miniport_init_parameters - A pointer to an NDIS_MINIPORT_INIT_PARAMETERS
//    structure that defines the initialization parameters for the adapter.
_Use_decl_annotations_ NDIS_STATUS GvnicInitialize(
    NDIS_HANDLE miniport_adapter_handle, NDIS_HANDLE miniport_driver_context,
    PNDIS_MINIPORT_INIT_PARAMETERS miniport_init_parameters) {
  PAGED_CODE();
  UNREFERENCED_PARAMETER(miniport_driver_context);
  DEBUGP(GVNIC_VERBOSE, "---> GvnicInitialize\n");

  NDIS_STATUS status = NDIS_STATUS_SUCCESS;
  AdapterContext* adapter_context =
      static_cast<AdapterContext*>(NdisAllocateMemoryWithTagPriority(
          miniport_adapter_handle, sizeof(AdapterContext), kGvnicMemoryTag,
          NormalPoolPriority));

  if (!adapter_context) {
    DEBUGP(GVNIC_ERROR, "[%s] ERROR: Memory allocation failed!\n",
           __FUNCTION__);
    status = NDIS_STATUS_RESOURCES;
  } else {
    // Required for Static Driver Verifier
    __sdv_save_adapter_context(adapter_context);
    NdisZeroMemory(adapter_context, sizeof(AdapterContext));
    status = InitializeAdapterContext(adapter_context, miniport_adapter_handle,
                                      miniport_init_parameters);
  }

  if (adapter_context && status != NDIS_STATUS_SUCCESS &&
      status != NDIS_STATUS_PENDING) {
    GvnicFreeMemory(adapter_context);
    adapter_context = nullptr;
  }

  DEBUGP(GVNIC_VERBOSE, "<--- GvnicInitialize status 0x%08x\n", status);
  return status;
}

// Called by NDIS to free resources when a miniport adapter is removed,
// and to stop the hardware.
//
// Arguments:
//   miniport_adapter_context - A handle to a context area that the miniport
//     driver allocated in its MiniportInitializeEx function.
//   halt_action - The reason for halting the miniport adapter.
_Use_decl_annotations_ VOID GvnicHalt(NDIS_HANDLE miniport_adapter_context,
                                      NDIS_HALT_ACTION halt_action) {
  PAGED_CODE();
  UNREFERENCED_PARAMETER(halt_action);
  DEBUGP(GVNIC_VERBOSE, "---> GvnicHalt");

  AdapterContext* context =
      static_cast<AdapterContext*>(miniport_adapter_context);
  GvnicFreeMemory(context);

  DEBUGP(GVNIC_VERBOSE, "<--- GvnicHalt");
}

// Called by NDIS to stop the flow of network data.
//
// Arguments:
//   miniport_adapter_context - A handle to a context area that the miniport
//    driver allocated in its MiniportInitializeEx function.
_Use_decl_annotations_ NDIS_STATUS GvnicPause(
    NDIS_HANDLE miniport_adapter_context, PNDIS_MINIPORT_PAUSE_PARAMETERS) {
  PAGED_CODE();
  DEBUGP(GVNIC_VERBOSE, "---> GvnicPause");

  auto adapter = static_cast<AdapterContext*>(miniport_adapter_context);

  NDIS_STATUS status = adapter->device.Pause();

  if (status != NDIS_STATUS_SUCCESS) {
    adapter->device.Reset(&adapter->resources, &adapter->statistics,
                          adapter->configuration);
  }

  DEBUGP(GVNIC_VERBOSE, "<--- GvnicPause");
  return status;
}

// Initiates a restart request for a miniport adapter that is paused.
//
// Arguments:
//   miniport_adapter_context - A handle to a context area that the miniport
//    driver allocated in its MiniportInitializeEx function.
_Use_decl_annotations_ NDIS_STATUS GvnicRestart(
    NDIS_HANDLE miniport_adapter_context, PNDIS_MINIPORT_RESTART_PARAMETERS) {
  PAGED_CODE();
  DEBUGP(GVNIC_VERBOSE, "---> GvnicRestart");

  auto adapter = static_cast<AdapterContext*>(miniport_adapter_context);

  NDIS_STATUS status = adapter->device.Restart();

  if (status != NDIS_STATUS_SUCCESS) {
    adapter->device.Reset(&adapter->resources, &adapter->statistics,
                          adapter->configuration);
  }

  DEBUGP(GVNIC_VERBOSE, "<--- GvnicRestart status %#X", status);
  return status;
}

// Called by NDIS when the system is shutting down.
//
// Arguments:
//   miniport_adapter_context - A handle to a context area that the miniport
//    driver allocated in its MiniportInitializeEx function.
//   shutdown_action - The reason why NDIS called the shutdown function.
//    NdisShutdownPowerOff or NdisShutdownBugCheck.
_Use_decl_annotations_ VOID
GvnicAdapterShutdown(NDIS_HANDLE miniport_adapter_context,
                     NDIS_SHUTDOWN_ACTION shutdown_action) {
  UNREFERENCED_PARAMETER(shutdown_action);
  UNREFERENCED_PARAMETER(miniport_adapter_context);
  DEBUGP(GVNIC_VERBOSE, "---> GvnicAdapterShutdown\n");

  if (shutdown_action == NdisShutdownBugCheck) {
    // This is called at a high IRQL, and any actions taken here must be
    // allowable at high IRQLs. Do not attempt to free resources.
    return;
  }

  // We rely on GvnicHalt to free resources and deconfigure the device, so no
  // additional work is currently being done in the shutdown handler.
  DEBUGP(GVNIC_VERBOSE, "<--- GvnicAdapterShutdown\n");
}

// Called by NDIS to notify the driver of Plug and Play (PnP) events.
//
// Arguments:
//   miniport_adapter_context - A handle to a context area that the miniport
//    driver allocated in its MiniportInitializeEx function.
//   net_device_pnp_event - A pointer to a NET_DEVICE_PNP_EVENT structure that
//    describes a device Plug and Play event.
_Use_decl_annotations_ VOID
GvnicDevicePnPEvent(NDIS_HANDLE miniport_adapter_context,
                    PNET_DEVICE_PNP_EVENT net_device_pnp_event) {
  PAGED_CODE();
  UNREFERENCED_PARAMETER(miniport_adapter_context);
  UNREFERENCED_PARAMETER(net_device_pnp_event);
  DEBUGP(GVNIC_VERBOSE, "---> GvnicDevicePnPEvent\n");

  // Surprise removal of the gVNIC virtual device is not supported. If the
  // system somehow gets into this state, nothing needs to be done as GvnicHalt
  // will be invoked immediately after which will pause queues and free memory.
  DEBUGP(GVNIC_VERBOSE, "<--- GvnicDevicePnPEvent\n");
}

// To establish a context area for an added device by initializing
// NDIS_MINIPORT_ADD_DEVICE_REGISTRATION_ATTRIBUTES structure.
//
// Arguments:
//   miniport_adapter_handle - An NDIS handle that identifies the miniport
//     adapter that the Plug and Play (PnP) manager is adding.
//   miniport_driver_context - A handle to a driver-allocated context area where
//     the driver maintains state and configuration information.
_Use_decl_annotations_ NDIS_STATUS
GvnicAddDevice(_In_ NDIS_HANDLE miniport_adapter_handle,
               _In_ NDIS_HANDLE miniport_driver_context) {
  PAGED_CODE();
  UNREFERENCED_PARAMETER(miniport_driver_context);
  DEBUGP(GVNIC_VERBOSE, "---> GvnicAddDevice\n");

  NDIS_MINIPORT_ADAPTER_ATTRIBUTES miniport_attrs;
  miniport_attrs.AddDeviceRegistrationAttributes.Header.Type =
      NDIS_OBJECT_TYPE_MINIPORT_ADD_DEVICE_REGISTRATION_ATTRIBUTES;
  miniport_attrs.AddDeviceRegistrationAttributes.Header.Revision =
      NDIS_MINIPORT_ADD_DEVICE_REGISTRATION_ATTRIBUTES_REVISION_1;
  miniport_attrs.AddDeviceRegistrationAttributes.Header.Size =
      NDIS_SIZEOF_MINIPORT_ADD_DEVICE_REGISTRATION_ATTRIBUTES_REVISION_1;
  miniport_attrs.AddDeviceRegistrationAttributes.MiniportAddDeviceContext =
      miniport_adapter_handle;
  miniport_attrs.AddDeviceRegistrationAttributes.Flags = 0;  // Reserved.

  NDIS_STATUS status =
      NdisMSetMiniportAttributes(miniport_adapter_handle, &miniport_attrs);

  DEBUGP(GVNIC_VERBOSE, "<--- GvnicAddDevice\n");
  return status;
}

// To releases resources that the MiniportAddDevice function allocated.
//
// Arguments:
//   miniport_add_device_context - A handle for a driver-allocated context area
//    that the miniport driver registered in the MiniportAddDevice function.
_Use_decl_annotations_ VOID
GvnicRemoveDevice(_In_ NDIS_HANDLE miniport_add_device_context) {
  PAGED_CODE();
  UNREFERENCED_PARAMETER(miniport_add_device_context);
  DEBUGP(GVNIC_VERBOSE, "---> GvnicRemoveDevice\n");

  DEBUGP(GVNIC_VERBOSE, "<--- GvnicRemoveDevice\n");
}

// Modify the resource requirements for a device.
// Mainly for adjusting MSI-X settings.
//
// NDIS may call MiniportFilterResourceRequirements while the miniport is
// running. While the miniport may modify the resource list as described below,
// the miniport should not immediately attempt to use the new resources. NDIS
// will eventually halt and re-initialize the miniport with the new resources;
// only then should the miniport attempt to use the new resources.
//
// Arguments:
//   miniport_add_device_context - A handle for a driver-allocated context area
//    that the miniport driver registered in the MiniportAddDevice function.
//   irp - The IRP_MN_FILTER_RESOURCE_REQUIREMENTS request to handle.
_Use_decl_annotations_ NDIS_STATUS GvnicFilterResource(
    _In_ NDIS_HANDLE miniport_add_device_context, _In_ PIRP irp) {
  PAGED_CODE();
  DEBUGP(GVNIC_VERBOSE, "---> GvnicFilterResource");

  auto resource_list = reinterpret_cast<IO_RESOURCE_REQUIREMENTS_LIST*>(
      irp->IoStatus.Information);

  NT_ASSERT(resource_list != nullptr);

  UINT processor_count = GetSystemProcessorCount();

  // Prepare the msi with best scenario: one vector per processor for all
  // queues.
  UINT num_tx = min(processor_count, kMaxPerDirectionTrafficSlices);
  UINT num_rx = min(processor_count, kMaxPerDirectionTrafficSlices);
  UINT num_msi = GetMsiVectorCount(*resource_list);

  // Need at least three msi(1 mgt, 1 tx and 1 rx) for the driver to work
  // correctly.
  if (num_msi < 3) {
    return NDIS_STATUS_RESOURCES;
  }

  // Reserve one msi for management queue.
  UINT msi_for_transmission = num_msi - 1;

  UINT rx_scale_factor = 1;

  // Expect one tx and rx per processor and one mgt queue.
  // If get less, adjust num_tx and num_rx
  if (msi_for_transmission < 2 * processor_count) {
    // Configure one msi per processor. Distribute the remaining msi equally
    // between tx and rx. If the number is odd, give the extra to rx.
    num_tx = msi_for_transmission / 2;
    num_rx = msi_for_transmission - num_tx;

    // If we have num_rx < half of processor count, we can skip the SMT vCPU'
    // since Windows will not use them any way.
    if (num_rx <= (processor_count / 2)) {
      rx_scale_factor = 2;
    }
  }

  // Get the RSS processor information. The default MSI configuration will
  // assume that the driver is going to use RSS. The first call gets the size
  // of the required buffer, and the next call fills the buffer with the system
  // settings.
  SIZE_T size = 0;
  PNDIS_RSS_PROCESSOR_INFO rss_processor_info = nullptr;
  NDIS_STATUS status = NdisGetRssProcessorInformation(
      miniport_add_device_context, /*RssProcessorInfo=*/nullptr, &size);
  if (status != NDIS_STATUS_BUFFER_TOO_SHORT || size == 0) {
    DEBUGP(GVNIC_WARNING,
           "[%s] WARNING: Unable to query system for the size of the memory "
           "allocation needed to query RSS processors.",
           __FUNCTION__);
  } else {
    rss_processor_info =
        static_cast<PNDIS_RSS_PROCESSOR_INFO>(NdisAllocateMemoryWithTagPriority(
            miniport_add_device_context, static_cast<ULONG>(size),
            kGvnicMemoryTag, NormalPoolPriority));
    if (rss_processor_info == nullptr) {
      DEBUGP(GVNIC_ERROR,
             "[%s] ERROR: Unable to allocate %u bytes to query system for RSS "
             "processor information.",
             __FUNCTION__, static_cast<ULONG>(size));
    } else {
      NdisZeroMemory(rss_processor_info, size);
      status = NdisGetRssProcessorInformation(miniport_add_device_context,
                                              rss_processor_info, &size);
      if (status != NDIS_STATUS_SUCCESS) {
        DEBUGP(GVNIC_WARNING,
               "[%s] WARNING: Unable to query system for RSS processors.",
               __FUNCTION__);
        NdisFreeMemory(rss_processor_info, 0, 0);
        rss_processor_info = nullptr;
      }
    }
  }

  SetMsiAffinity(num_tx, num_rx, rx_scale_factor, rss_processor_info,
                 resource_list);

  if (rss_processor_info != nullptr) {
    if (rss_processor_info->RssProcessorCount > num_rx) {
      IO_RESOURCE_REQUIREMENTS_LIST* new_list =
          RequestAdditionalMsiResourcesForRss(resource_list, rss_processor_info,
                                              num_rx, num_tx,
                                              miniport_add_device_context);
      if (new_list == nullptr) {
        DEBUGP(GVNIC_WARNING,
               "[%s] WARNING: Unable to create and configure a new resource "
               "list to allow changing slice affinities to match complex "
               "indirection tables.",
               __FUNCTION__);
      } else {
        // A driver takes ownership of an IRP when it receives it, so we can
        // simply free the existing list (although this might look strange).
        NdisFreeMemory(resource_list, 0, 0);
        irp->IoStatus.Information = reinterpret_cast<ULONG_PTR>(new_list);

        DEBUGP(GVNIC_INFO,
               "[%s]: Requested %d additional MSI resources to allow changing "
               "slice affinities to any RSS processor.",
               __FUNCTION__, rss_processor_info->RssProcessorCount - num_rx);
      }
    }
    NdisFreeMemory(rss_processor_info, 0, 0);
  }

  irp->IoStatus.Status = STATUS_SUCCESS;

  DEBUGP(GVNIC_VERBOSE, "<--- GvnicFilterResource");
  return NDIS_STATUS_SUCCESS;
}

// Called before MiniportInitializeEx to clean up resource modified by
// GvnicFilterResource.
//
// Arguments:
//   miniport_add_device_context - A handle for a driver-allocated context area
//    that the miniport driver registered in the MiniportAddDevice function.
//   irp - A pointer to an IRP_MN_START_DEVICE IRP.
_Use_decl_annotations_ NDIS_STATUS
GvnicStartDevice(_In_ NDIS_HANDLE miniport_add_device_context, _In_ PIRP irp) {
  PAGED_CODE();
  UNREFERENCED_PARAMETER(miniport_add_device_context);
  UNREFERENCED_PARAMETER(irp);
  DEBUGP(GVNIC_VERBOSE, "---> GvnicStartDevice\n");

  NDIS_STATUS status = NDIS_STATUS_SUCCESS;

  DEBUGP(GVNIC_VERBOSE, "<--- GvnicStartDevice\n");
  return status;
}

// NDIS calls the MiniportReturnNetBufferLists function to return ownership of
// NET_BUFFER_LIST structures, associated NET_BUFFER structures, and any
// attached MDLs to a miniport driver.
//
// Arguments:
//   miniport_adapter_context - A handle to a context area that the miniport
//    driver allocated in its MiniportInitializeEx function.
//   net_buffer_lists - A pointer to a linked list of NET_BUFFER_LIST structures
//    that NDIS is returning to the miniport driver.
//   return_flags - NDIS flags that can be combined with an OR operation. This
//    function supports the NDIS_RETURN_FLAGS_DISPATCH_LEVEL flag which, if set,
//    indicates that the current IRQL is DISPATCH_LEVEL.
VOID GvnicReturnNetBufferLists(NDIS_HANDLE miniport_adapter_context,
                               PNET_BUFFER_LIST net_buffer_lists,
                               ULONG return_flags) {
  UNREFERENCED_PARAMETER(miniport_adapter_context);
  UNREFERENCED_PARAMETER(return_flags);

  DEBUGP(GVNIC_VERBOSE, "---> GvnicReturnNetBufferLists");
  while (net_buffer_lists != nullptr) {
    NET_BUFFER_LIST* nbl_to_free = net_buffer_lists;
    net_buffer_lists = NET_BUFFER_LIST_NEXT_NBL(net_buffer_lists);
    NET_BUFFER_LIST_NEXT_NBL(nbl_to_free) = nullptr;
    FreeMdlsFromReceiveNetBuffer(NET_BUFFER_LIST_FIRST_NB(nbl_to_free));
    DecreaseRxDataRingPendingCount(nbl_to_free);
  }
  DEBUGP(GVNIC_VERBOSE, "<--- GvnicReturnNetBufferLists");
}

// NDIS calls the MiniportSendNetBufferLists function to transmit network data
// that is contained in a linked list of NET_BUFFER_LIST structures.
//
// Arguments:
//   miniport_adapter_context - A handle to a context area that the miniport
//    driver allocated in its MiniportInitializeEx function.
//   net_buffer_lists - A pointer to the first NET_BUFFER_LIST structure in a
//    linked list of NET_BUFFER_LIST structures.
//   port_number - A port number that identifies a miniport adapter port.
//   send_flags - Define attributes for the send operation.
VOID GvnicSendNetBufferLists(NDIS_HANDLE miniport_adapter_context,
                             PNET_BUFFER_LIST net_buffer_list,
                             NDIS_PORT_NUMBER port_number, ULONG send_flags) {
  UNREFERENCED_PARAMETER(port_number);
  AdapterContext* context =
      static_cast<AdapterContext*>(miniport_adapter_context);
  bool is_dpc_level = ((NDIS_SEND_FLAGS_DISPATCH_LEVEL & send_flags) != 0);
  context->device.SendNetBufferLists(net_buffer_list, is_dpc_level);
}

// NDIS calls a miniport driver's MiniportCancelSend function to cancel the
// transmission of all NET_BUFFER_LIST structures that are marked with a
// specified cancellation identifier.
//
// Arguments:
//   miniport_adapter_context - A handle to a context area that the miniport
//    driver allocated in its MiniportInitializeEx function.
//   cancel_id - A cancellation identifier. This identifier specifies the
//    NET_BUFFER_LIST structures that are being canceled.
VOID GvnicCancelSendNetBufferLists(NDIS_HANDLE miniport_adapter_context,
                                   PVOID cancel_id) {
  UNREFERENCED_PARAMETER(miniport_adapter_context);
  UNREFERENCED_PARAMETER(cancel_id);

  // TODO(b/174525218): Support cancelling queued NET_BUFFER_LISTs.
}
