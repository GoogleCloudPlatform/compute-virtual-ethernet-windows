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

#include "adapter_configuration.h"  // NOLINT: include directory

#include <ndis.h>

#include "netutils.h"  // NOLINT: include directory
#include "trace.h"  // NOLINT: include directory

#include "adapter_configuration.tmh"  // NOLINT: trace message header

namespace {

constexpr int kTxChecksumOffloadEnabled = 1;
constexpr int kRxChecksumOffloadEnabled = 1 << 1;

// This is a wrapper function of NdisInitializeString, which requests a
// non-constant UCHAR* as input. According to function doc, it won't change
// the source_string. Safely strip the const-ness of input string.
void InitializeNdisString(NDIS_STRING& destination_string,
                          const char* source_string) {
  PAGED_CODE();
  NdisInitializeString(
      &destination_string,
      const_cast<UCHAR*>(reinterpret_cast<const UCHAR*>(source_string)));
}

// Read configuration from registry.
void GetConfigurationEntry(NDIS_HANDLE configuration_handle,
                           ConfigurationEntry* entry) {
  PAGED_CODE();
  NDIS_STATUS status;
  NDIS_STRING name = {};
  InitializeNdisString(name, entry->name);
  PNDIS_CONFIGURATION_PARAMETER param = nullptr;

  NdisReadConfiguration(&status, &param, configuration_handle, &name,
                        NdisParameterInteger);

  if (status == NDIS_STATUS_SUCCESS) {
    ULONG value = param->ParameterData.IntegerData;

    if (value >= entry->min_limit && value <= entry->max_limit) {
      entry->value = value;
      DEBUGP(GVNIC_INFO, "[%s] read for %s - 0x%x\n", __FUNCTION__, entry->name,
             entry->value);
    } else {
      DEBUGP(GVNIC_WARNING, "[%s] read out of range value 0x%X\n", __FUNCTION__,
             value);
    }
  } else {
    DEBUGP(GVNIC_WARNING, "[%s] read value for %s failed with status 0x%X\n",
           __FUNCTION__, entry->name, status);
  }

  if (name.Buffer) {
    NdisFreeString(name);
  }
}

// Open NDIS registry for read.
NDIS_HANDLE OpenNICConfiguration(NDIS_HANDLE miniport_handle) {
  PAGED_CODE();
  DEBUGP(GVNIC_VERBOSE, "---> OpenNICConfiguration\n");

  NDIS_CONFIGURATION_OBJECT configuration_object;
  configuration_object.Header.Type = NDIS_OBJECT_TYPE_CONFIGURATION_OBJECT;
  configuration_object.Header.Revision = NDIS_CONFIGURATION_OBJECT_REVISION_1;
  configuration_object.Header.Size =
      NDIS_SIZEOF_CONFIGURATION_OBJECT_REVISION_1;
  configuration_object.Flags = 0;
  configuration_object.NdisHandle = miniport_handle;

  NDIS_HANDLE configuration_handle;
  NDIS_STATUS status =
      NdisOpenConfigurationEx(&configuration_object, &configuration_handle);

  if (status != NDIS_STATUS_SUCCESS) {
    configuration_handle = NULL;
  }

  DEBUGP(GVNIC_VERBOSE, "<--- OpenNICConfiguration status 0x%08x\n", status);
  return configuration_handle;
}

}  // namespace

void AdapterConfiguration::LoadDefaultValue() {
  PAGED_CODE();
  mtu_ = {"MTU", 1460, 576, 65500};

  // Link:
  // https://docs.microsoft.com/en-us/windows-hardware/drivers/network/using-registry-values-to-enable-and-disable-task-offloading
  // Check sum config has value from 0 - 3
  // 0 - Disabled
  // 1 - Tx Enabled
  // 2 - Rx Enabled
  // 3 - Rx & Tx Enabled
  tcp_checksum_offload_ipv4_ = {"*TCPChecksumOffloadIPv4", 3, 0, 3};
  tcp_checksum_offload_ipv6_ = {"*TCPChecksumOffloadIPv6", 3, 0, 3};
  udp_checksum_offload_ipv4_ = {"*UDPChecksumOffloadIPv4", 3, 0, 3};
  udp_checksum_offload_ipv6_ = {"*UDPChecksumOffloadIPv6", 3, 0, 3};

  // LSO config. 0 - Disabled. 1 - Enabled.
  lso_v2_ipv4_ = {"*LsoV2IPv4", 1, 0, 1};
  lso_v2_ipv6_ = {"*LsoV2IPv6", 1, 0, 1};

  // number of tx/rx queue. 0 means not configured.
  // Assuming worst case 100 cores with 8 tx queue and 1 rx queue per core.
  num_tx_queue_ = {"NumberOfTxQueue", 0, 0, 800};
  num_rx_queue_ = {"NumberOfRxQueue", 0, 0, 100};

  // RSS config, 0 - Disabled, 1 - Enabled.
  rss_ = {"*RSS", 1, 0, 1};

  // RSC config, 0 - Disabled, 1 - Enabled.
  rsc_ipv4_ = {"*RscIPv4", 1, 0, 1};
  rsc_ipv6_ = {"*RscIPv6", 1, 0, 1};
}

void AdapterConfiguration::Initialize(NDIS_HANDLE miniport_handle) {
  PAGED_CODE();
  DEBUGP(GVNIC_VERBOSE, "---> AdapterConfiguration::Initialize\n");

  LoadDefaultValue();

  NDIS_HANDLE configuration_handle = OpenNICConfiguration(miniport_handle);
  if (configuration_handle) {
    GetConfigurationEntry(configuration_handle, &mtu_);
    GetConfigurationEntry(configuration_handle, &tcp_checksum_offload_ipv4_);
    GetConfigurationEntry(configuration_handle, &tcp_checksum_offload_ipv6_);
    GetConfigurationEntry(configuration_handle, &udp_checksum_offload_ipv4_);
    GetConfigurationEntry(configuration_handle, &udp_checksum_offload_ipv6_);
    GetConfigurationEntry(configuration_handle, &lso_v2_ipv4_);
    GetConfigurationEntry(configuration_handle, &lso_v2_ipv6_);
    GetConfigurationEntry(configuration_handle, &num_tx_queue_);
    GetConfigurationEntry(configuration_handle, &num_rx_queue_);
    GetConfigurationEntry(configuration_handle, &rss_);
    GetConfigurationEntry(configuration_handle, &rsc_ipv4_);
    GetConfigurationEntry(configuration_handle, &rsc_ipv6_);

    // Read Mac address.
    PVOID network_addr;
    UINT length = 0;
    NDIS_STATUS status;
    NdisReadNetworkAddress(&status, &network_addr, &length,
                           configuration_handle);
    if (status == NDIS_STATUS_SUCCESS && length == kEthAddrLen) {
      is_mac_configured_ = true;
      NdisMoveMemory(&mac_, network_addr, length);
      LogMacAddress("Mac from registry:", mac_);
    } else if (length && length != kEthAddrLen) {
      DEBUGP(GVNIC_ERROR, "[%s] MAC address has wrong length of %d\n",
             __FUNCTION__, length);
    } else {
      DEBUGP(GVNIC_INFO, "[%s] Nothing read for MAC, error %X\n", __FUNCTION__,
             status);
    }

    NdisCloseConfiguration(configuration_handle);
  } else {
    DEBUGP(GVNIC_WARNING,
           "Open NIC configuration failed. Use default values.\n");
  }

  DEBUGP(GVNIC_VERBOSE, "<--- AdapterConfiguration::Initialize");
}

bool AdapterConfiguration::is_tx_tcp_checksum_offload_ipv4_enabled() const {
  return (tcp_checksum_offload_ipv4_.value & kTxChecksumOffloadEnabled) != 0;
}

bool AdapterConfiguration::is_tx_tcp_checksum_offload_ipv6_enabled() const {
  return (tcp_checksum_offload_ipv6_.value & kTxChecksumOffloadEnabled) != 0;
}

bool AdapterConfiguration::is_rx_tcp_checksum_offload_ipv4_enabled() const {
  return (tcp_checksum_offload_ipv4_.value & kRxChecksumOffloadEnabled) != 0;
}

bool AdapterConfiguration::is_rx_tcp_checksum_offload_ipv6_enabled() const {
  return (tcp_checksum_offload_ipv6_.value & kRxChecksumOffloadEnabled) != 0;
}

bool AdapterConfiguration::is_tx_udp_checksum_offload_ipv4_enabled() const {
  return (udp_checksum_offload_ipv4_.value & kTxChecksumOffloadEnabled) != 0;
}

bool AdapterConfiguration::is_tx_udp_checksum_offload_ipv6_enabled() const {
  return (udp_checksum_offload_ipv6_.value & kTxChecksumOffloadEnabled) != 0;
}

bool AdapterConfiguration::is_rx_udp_checksum_offload_ipv4_enabled() const {
  return (udp_checksum_offload_ipv4_.value & kRxChecksumOffloadEnabled) != 0;
}

bool AdapterConfiguration::is_rx_udp_checksum_offload_ipv6_enabled() const {
  return (udp_checksum_offload_ipv6_.value & kRxChecksumOffloadEnabled) != 0;
}
