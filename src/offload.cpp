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

#include "offload.h"  // NOLINT: include directory

#include <ndis.h>

#include "netutils.h"  // NOLINT: include directory
#include "trace.h"  // NOLINT: include directory

#include "offload.tmh"  // NOLINT: trace message header

namespace {
// max LSO size for TCP. Descriptor has 16 bit int for length. Reserve enough
// space for ETH_HEADER, IPHeader, TcpHeader.
constexpr int kMaxOffloadSize =
    MAXUINT16 - kMaxEthHeaderSize - kMaxIPHeaderSize - kMaxTcpHeaderSize;

// The minimum number of segments that a large TCP packet must be divisible by
// before the transport can offload it to the hardware for segmentation.
constexpr int kLsoMinSegmentCount = 2;

void SetNdisOffloadHeader(NDIS_OFFLOAD* ndis_offload) {
  ndis_offload->Header.Type = NDIS_OBJECT_TYPE_OFFLOAD;
#if NDIS_SUPPORT_NDIS630
  ndis_offload->Header.Revision = NDIS_OFFLOAD_REVISION_3;
  ndis_offload->Header.Size = NDIS_SIZEOF_NDIS_OFFLOAD_REVISION_3;
#elif NDIS_SUPPORT_NDIS61
  ndis_offload->Header.Revision = NDIS_OFFLOAD_REVISION_2;
  ndis_offload->Header.Size = NDIS_SIZEOF_NDIS_OFFLOAD_REVISION_2;
#else
  ndis_offload->Header.Revision = NDIS_OFFLOAD_REVISION_1;
  ndis_offload->Header.Size = NDIS_SIZEOF_NDIS_OFFLOAD_REVISION_1;
#endif
  ndis_offload->Checksum.IPv4Receive.Encapsulation =
      NDIS_ENCAPSULATION_IEEE_802_3;
  ndis_offload->Checksum.IPv4Transmit.Encapsulation =
      NDIS_ENCAPSULATION_IEEE_802_3;
  ndis_offload->Checksum.IPv6Receive.Encapsulation =
      NDIS_ENCAPSULATION_IEEE_802_3;
  ndis_offload->Checksum.IPv6Receive.Encapsulation =
      NDIS_ENCAPSULATION_IEEE_802_3;
}

// ULONG type to match the setting type in NDIS_OFFLOAD. The value can only be
// 0 or 1.
const char* GetOffloadSettingString(ULONG tx_enabled, ULONG rx_enabled) {
  UINT32 idx = tx_enabled + 2 * rx_enabled;
  switch (idx) {
    case 0:
      return "Disabled";
    case 1:
      return "Tx";
    case 2:
      return "Rx";
    case 3:
      return "TxRx";
    default:
      break;
  }
  return "Out of Range";
}

// Validate the new offload config against capability.
// Return false if the config is invalid and true otherwise.
bool ValidateOffloadConfig(const NDIS_OFFLOAD& config,
                           const NDIS_OFFLOAD& capability) {
  if (capability.Checksum.IPv4Receive.IpChecksum ==
          NDIS_OFFLOAD_NOT_SUPPORTED &&
      config.Checksum.IPv4Receive.IpChecksum == NDIS_OFFLOAD_SUPPORTED) {
    return false;
  }

  if (capability.Checksum.IPv4Receive.TcpChecksum ==
          NDIS_OFFLOAD_NOT_SUPPORTED &&
      config.Checksum.IPv4Receive.TcpChecksum == NDIS_OFFLOAD_SUPPORTED) {
    return false;
  }

  if (capability.Checksum.IPv4Receive.UdpChecksum ==
          NDIS_OFFLOAD_NOT_SUPPORTED &&
      config.Checksum.IPv4Receive.UdpChecksum == NDIS_OFFLOAD_SUPPORTED) {
    return false;
  }

  if (capability.Checksum.IPv4Transmit.IpChecksum ==
          NDIS_OFFLOAD_NOT_SUPPORTED &&
      config.Checksum.IPv4Transmit.IpChecksum == NDIS_OFFLOAD_SUPPORTED) {
    return false;
  }

  if (capability.Checksum.IPv4Transmit.TcpChecksum ==
          NDIS_OFFLOAD_NOT_SUPPORTED &&
      config.Checksum.IPv4Transmit.TcpChecksum == NDIS_OFFLOAD_SUPPORTED) {
    return false;
  }

  if (capability.Checksum.IPv4Transmit.UdpChecksum ==
          NDIS_OFFLOAD_NOT_SUPPORTED &&
      config.Checksum.IPv4Transmit.UdpChecksum == NDIS_OFFLOAD_SUPPORTED) {
    return false;
  }

  if (capability.Checksum.IPv6Receive.TcpChecksum ==
          NDIS_OFFLOAD_NOT_SUPPORTED &&
      config.Checksum.IPv6Receive.TcpChecksum == NDIS_OFFLOAD_SUPPORTED) {
    return false;
  }

  if (capability.Checksum.IPv6Receive.UdpChecksum ==
          NDIS_OFFLOAD_NOT_SUPPORTED &&
      config.Checksum.IPv6Receive.UdpChecksum == NDIS_OFFLOAD_SUPPORTED) {
    return false;
  }

  if (capability.Checksum.IPv6Transmit.TcpChecksum ==
          NDIS_OFFLOAD_NOT_SUPPORTED &&
      config.Checksum.IPv6Transmit.TcpChecksum == NDIS_OFFLOAD_SUPPORTED) {
    return false;
  }

  if (capability.Checksum.IPv6Transmit.UdpChecksum ==
          NDIS_OFFLOAD_NOT_SUPPORTED &&
      config.Checksum.IPv6Transmit.UdpChecksum == NDIS_OFFLOAD_SUPPORTED) {
    return false;
  }

  if (capability.LsoV1.IPv4.Encapsulation == NDIS_ENCAPSULATION_NOT_SUPPORTED &&
      config.LsoV1.IPv4.Encapsulation != NDIS_ENCAPSULATION_IEEE_802_3) {
    return false;
  }

  if (capability.LsoV2.IPv4.Encapsulation == NDIS_ENCAPSULATION_NOT_SUPPORTED &&
      config.LsoV2.IPv4.Encapsulation != NDIS_ENCAPSULATION_IEEE_802_3) {
    return false;
  }

  if (capability.LsoV2.IPv6.Encapsulation == NDIS_ENCAPSULATION_NOT_SUPPORTED &&
      config.LsoV2.IPv6.Encapsulation != NDIS_ENCAPSULATION_IEEE_802_3) {
    return false;
  }

#ifdef SUPPORT_RSC
  if (!capability.Rsc.IPv4.Enabled && config.Rsc.IPv4.Enabled) {
    return false;
  }

  if (!capability.Rsc.IPv6.Enabled && config.Rsc.IPv6.Enabled) {
    return false;
  }
#endif

  return true;
}

// Apply src_config fields to dst_config.
// Return true if any change is made and false otherwise.
bool ApplyOffloadConfig(const NDIS_OFFLOAD& src_config,
                        NDIS_OFFLOAD* dst_config) {
  bool is_updated = false;
  if (src_config.Checksum.IPv4Receive.IpChecksum !=
      dst_config->Checksum.IPv4Receive.IpChecksum) {
    is_updated = true;
    dst_config->Checksum.IPv4Receive.IpChecksum =
        src_config.Checksum.IPv4Receive.IpChecksum;
  }

  if (src_config.Checksum.IPv4Receive.TcpChecksum !=
      dst_config->Checksum.IPv4Receive.TcpChecksum) {
    is_updated = true;
    dst_config->Checksum.IPv4Receive.TcpChecksum =
        src_config.Checksum.IPv4Receive.TcpChecksum;
  }

  if (src_config.Checksum.IPv4Receive.UdpChecksum !=
      dst_config->Checksum.IPv4Receive.UdpChecksum) {
    is_updated = true;
    dst_config->Checksum.IPv4Receive.UdpChecksum =
        src_config.Checksum.IPv4Receive.UdpChecksum;
  }

  if (src_config.Checksum.IPv4Transmit.IpChecksum !=
      dst_config->Checksum.IPv4Transmit.IpChecksum) {
    is_updated = true;
    dst_config->Checksum.IPv4Transmit.IpChecksum =
        src_config.Checksum.IPv4Transmit.IpChecksum;
  }

  if (src_config.Checksum.IPv4Transmit.TcpChecksum !=
      dst_config->Checksum.IPv4Transmit.TcpChecksum) {
    is_updated = true;
    dst_config->Checksum.IPv4Transmit.TcpChecksum =
        src_config.Checksum.IPv4Transmit.TcpChecksum;
  }

  if (src_config.Checksum.IPv4Transmit.UdpChecksum !=
      dst_config->Checksum.IPv4Transmit.UdpChecksum) {
    is_updated = true;
    dst_config->Checksum.IPv4Transmit.UdpChecksum =
        src_config.Checksum.IPv4Transmit.UdpChecksum;
  }

  if (src_config.Checksum.IPv6Receive.TcpChecksum !=
      dst_config->Checksum.IPv6Receive.TcpChecksum) {
    is_updated = true;
    dst_config->Checksum.IPv6Receive.TcpChecksum =
        src_config.Checksum.IPv6Receive.TcpChecksum;
  }

  if (src_config.Checksum.IPv6Receive.UdpChecksum !=
      dst_config->Checksum.IPv6Receive.UdpChecksum) {
    is_updated = true;
    dst_config->Checksum.IPv6Receive.UdpChecksum =
        src_config.Checksum.IPv6Receive.UdpChecksum;
  }

  if (src_config.Checksum.IPv6Transmit.TcpChecksum !=
      dst_config->Checksum.IPv6Transmit.TcpChecksum) {
    is_updated = true;
    dst_config->Checksum.IPv6Transmit.TcpChecksum =
        src_config.Checksum.IPv6Transmit.TcpChecksum;
  }

  if (src_config.Checksum.IPv6Transmit.UdpChecksum !=
      dst_config->Checksum.IPv6Transmit.UdpChecksum) {
    is_updated = true;
    dst_config->Checksum.IPv6Transmit.UdpChecksum =
        src_config.Checksum.IPv6Transmit.UdpChecksum;
  }

  if (src_config.LsoV1.IPv4.Encapsulation !=
      dst_config->LsoV1.IPv4.Encapsulation) {
    is_updated = true;
    dst_config->LsoV1.IPv4.Encapsulation = src_config.LsoV1.IPv4.Encapsulation;
  }

  if (src_config.LsoV2.IPv4.Encapsulation !=
      dst_config->LsoV2.IPv4.Encapsulation) {
    is_updated = true;
    dst_config->LsoV2.IPv4.Encapsulation = src_config.LsoV2.IPv4.Encapsulation;
  }

  if (src_config.LsoV2.IPv6.Encapsulation !=
      dst_config->LsoV2.IPv6.Encapsulation) {
    is_updated = true;
    dst_config->LsoV2.IPv6.Encapsulation = src_config.LsoV2.IPv6.Encapsulation;
  }

#ifdef SUPPORT_RSC
  if (src_config.Rsc.IPv4.Enabled != dst_config->Rsc.IPv4.Enabled) {
    is_updated = true;
    dst_config->Rsc.IPv4.Enabled = src_config.Rsc.IPv4.Enabled;
  }

  if (src_config.Rsc.IPv6.Enabled != dst_config->Rsc.IPv6.Enabled) {
    is_updated = true;
    dst_config->Rsc.IPv6.Enabled = src_config.Rsc.IPv6.Enabled;
  }
#endif
  return is_updated;
}

// Get checksum offload Setting from values inside NDIS_OFFLOAD_PARAMETERS.
UINT32 GetChecksumSetting(UINT32 checksum_setting, bool is_tx, UINT32 current) {
  switch (checksum_setting) {
    case NDIS_OFFLOAD_PARAMETERS_NO_CHANGE:
      return current;
    case NDIS_OFFLOAD_PARAMETERS_TX_RX_DISABLED:
      return NDIS_OFFLOAD_NOT_SUPPORTED;
    case NDIS_OFFLOAD_PARAMETERS_TX_ENABLED_RX_DISABLED:
      if (is_tx) {
        return NDIS_OFFLOAD_SUPPORTED;
      } else {
        return NDIS_OFFLOAD_NOT_SUPPORTED;
      }
    case NDIS_OFFLOAD_PARAMETERS_RX_ENABLED_TX_DISABLED:
      if (is_tx) {
        return NDIS_OFFLOAD_NOT_SUPPORTED;
      } else {
        return NDIS_OFFLOAD_SUPPORTED;
      }
    case NDIS_OFFLOAD_PARAMETERS_TX_RX_ENABLED:
      return NDIS_OFFLOAD_SUPPORTED;
    default:
      return current;
  }
}

void SendOffloadStatusIndication(NDIS_HANDLE miniport_handle,
                                 const NDIS_OFFLOAD& offload_config) {
  NDIS_STATUS_INDICATION indication = {};
  NDIS_OFFLOAD offload = offload_config;
  indication.Header.Type = NDIS_OBJECT_TYPE_STATUS_INDICATION;
  indication.Header.Revision = NDIS_STATUS_INDICATION_REVISION_1;
  indication.Header.Size = NDIS_SIZEOF_STATUS_INDICATION_REVISION_1;
  indication.SourceHandle = miniport_handle;
  indication.StatusCode = NDIS_STATUS_TASK_OFFLOAD_CURRENT_CONFIG;
  indication.StatusBuffer = &offload;
  indication.StatusBufferSize = sizeof(offload);
  LogOffloadSetting("Indicating offload change.", offload);
  NdisMIndicateStatusEx(miniport_handle, &indication);
}
}  // namespace

// By default, we support TCP, UDP checksum offload for both IPv4, IPv6.
// Gvnic doesn't support IP checksum offload.
void SetHardwareDefaultOffloadCapability(NDIS_OFFLOAD* default_offload) {
  SetNdisOffloadHeader(default_offload);
  // IPv4 Transmit
  default_offload->Checksum.IPv4Transmit.IpChecksum =
      NDIS_OFFLOAD_NOT_SUPPORTED;
  default_offload->Checksum.IPv4Transmit.IpOptionsSupported =
      NDIS_OFFLOAD_SUPPORTED;
  default_offload->Checksum.IPv4Transmit.TcpChecksum = NDIS_OFFLOAD_SUPPORTED;
  default_offload->Checksum.IPv4Transmit.TcpOptionsSupported =
      NDIS_OFFLOAD_SUPPORTED;
  default_offload->Checksum.IPv4Transmit.UdpChecksum = NDIS_OFFLOAD_SUPPORTED;

  // IPv6 Transmit
  default_offload->Checksum.IPv6Transmit.IpExtensionHeadersSupported =
      NDIS_OFFLOAD_SUPPORTED;
  default_offload->Checksum.IPv6Transmit.TcpChecksum = NDIS_OFFLOAD_SUPPORTED;
  default_offload->Checksum.IPv6Transmit.TcpOptionsSupported =
      NDIS_OFFLOAD_SUPPORTED;
  default_offload->Checksum.IPv6Transmit.UdpChecksum = NDIS_OFFLOAD_SUPPORTED;

  // IPv4 Receive
  default_offload->Checksum.IPv4Receive.IpChecksum = NDIS_OFFLOAD_SUPPORTED;
  default_offload->Checksum.IPv4Receive.IpOptionsSupported =
      NDIS_OFFLOAD_SUPPORTED;
  default_offload->Checksum.IPv4Receive.TcpChecksum = NDIS_OFFLOAD_SUPPORTED;
  default_offload->Checksum.IPv4Receive.TcpOptionsSupported =
      NDIS_OFFLOAD_SUPPORTED;
  default_offload->Checksum.IPv4Receive.UdpChecksum = NDIS_OFFLOAD_SUPPORTED;

  // IPv6 Receive
  default_offload->Checksum.IPv6Receive.IpExtensionHeadersSupported =
      NDIS_OFFLOAD_SUPPORTED;
  default_offload->Checksum.IPv6Receive.TcpChecksum = NDIS_OFFLOAD_SUPPORTED;
  default_offload->Checksum.IPv6Receive.TcpOptionsSupported =
      NDIS_OFFLOAD_SUPPORTED;
  default_offload->Checksum.IPv6Receive.UdpChecksum = NDIS_OFFLOAD_SUPPORTED;

  // LSOV1
  default_offload->LsoV1.IPv4.Encapsulation = NDIS_ENCAPSULATION_IEEE_802_3;
  default_offload->LsoV1.IPv4.MaxOffLoadSize = kMaxOffloadSize;
  default_offload->LsoV1.IPv4.MinSegmentCount = kLsoMinSegmentCount;
  default_offload->LsoV1.IPv4.IpOptions = NDIS_OFFLOAD_SUPPORTED;
  default_offload->LsoV1.IPv4.TcpOptions = NDIS_OFFLOAD_SUPPORTED;

  // LSOV2
  default_offload->LsoV2.IPv4.Encapsulation = NDIS_ENCAPSULATION_IEEE_802_3;
  default_offload->LsoV2.IPv4.MaxOffLoadSize = kMaxOffloadSize;
  default_offload->LsoV2.IPv4.MinSegmentCount = kLsoMinSegmentCount;

  default_offload->LsoV2.IPv6.Encapsulation = NDIS_ENCAPSULATION_IEEE_802_3;
  default_offload->LsoV2.IPv6.IpExtensionHeadersSupported =
      NDIS_OFFLOAD_SUPPORTED;
  default_offload->LsoV2.IPv6.MaxOffLoadSize = kMaxOffloadSize;
  default_offload->LsoV2.IPv6.MinSegmentCount = kLsoMinSegmentCount;
  default_offload->LsoV2.IPv6.TcpOptionsSupported = NDIS_OFFLOAD_SUPPORTED;

#ifdef SUPPORT_RSC
  // RSC
  default_offload->Rsc.IPv4.Enabled = true;
  default_offload->Rsc.IPv6.Enabled = true;
#endif
}

// Copy offload setting from adapter_config into offload_config.
// It will respect offload_capability and only disable features that are turned
// off.
void SetOffloadConfiguration(const AdapterConfiguration& adapter_config,
                             NDIS_OFFLOAD* offload_config) {
  NdisZeroMemory(offload_config, sizeof(NDIS_OFFLOAD));
  SetHardwareDefaultOffloadCapability(offload_config);  // reset all to default.

  if (!adapter_config.is_tx_tcp_checksum_offload_ipv4_enabled()) {
    offload_config->Checksum.IPv4Transmit.TcpChecksum =
        NDIS_OFFLOAD_NOT_SUPPORTED;
  }

  if (!adapter_config.is_tx_udp_checksum_offload_ipv4_enabled()) {
    offload_config->Checksum.IPv4Transmit.UdpChecksum =
        NDIS_OFFLOAD_NOT_SUPPORTED;
  }

  if (!adapter_config.is_tx_tcp_checksum_offload_ipv6_enabled()) {
    offload_config->Checksum.IPv6Transmit.TcpChecksum =
        NDIS_OFFLOAD_NOT_SUPPORTED;
  }

  if (!adapter_config.is_tx_udp_checksum_offload_ipv6_enabled()) {
    offload_config->Checksum.IPv6Transmit.UdpChecksum =
        NDIS_OFFLOAD_NOT_SUPPORTED;
  }

  if (!adapter_config.is_rx_tcp_checksum_offload_ipv4_enabled()) {
    offload_config->Checksum.IPv4Receive.TcpChecksum =
        NDIS_OFFLOAD_NOT_SUPPORTED;
  }

  if (!adapter_config.is_rx_udp_checksum_offload_ipv4_enabled()) {
    offload_config->Checksum.IPv4Receive.UdpChecksum =
        NDIS_OFFLOAD_NOT_SUPPORTED;
  }

  if (!adapter_config.is_rx_tcp_checksum_offload_ipv6_enabled()) {
    offload_config->Checksum.IPv6Receive.TcpChecksum =
        NDIS_OFFLOAD_NOT_SUPPORTED;
  }

  if (!adapter_config.is_rx_udp_checksum_offload_ipv6_enabled()) {
    offload_config->Checksum.IPv6Receive.UdpChecksum =
        NDIS_OFFLOAD_NOT_SUPPORTED;
  }

  if (!adapter_config.is_lso_v2_ipv4_enabled()) {
    offload_config->LsoV1.IPv4.Encapsulation = NDIS_ENCAPSULATION_NOT_SUPPORTED;
    offload_config->LsoV1.IPv4.IpOptions = NDIS_OFFLOAD_NOT_SUPPORTED;
    offload_config->LsoV1.IPv4.TcpOptions = NDIS_OFFLOAD_NOT_SUPPORTED;
    offload_config->LsoV1.IPv4.MaxOffLoadSize = 0;
    offload_config->LsoV1.IPv4.MinSegmentCount = 0;

    offload_config->LsoV2.IPv4.Encapsulation = NDIS_ENCAPSULATION_NOT_SUPPORTED;
    offload_config->LsoV2.IPv4.MaxOffLoadSize = 0;
    offload_config->LsoV2.IPv4.MinSegmentCount = 0;
  }

  if (!adapter_config.is_lso_v2_ipv6_enabled()) {
    offload_config->LsoV2.IPv6.Encapsulation = NDIS_ENCAPSULATION_NOT_SUPPORTED;
    offload_config->LsoV2.IPv6.IpExtensionHeadersSupported =
        NDIS_OFFLOAD_NOT_SUPPORTED;
    offload_config->LsoV2.IPv6.TcpOptionsSupported = NDIS_OFFLOAD_NOT_SUPPORTED;
    offload_config->LsoV2.IPv6.MaxOffLoadSize = 0;
    offload_config->LsoV2.IPv6.MinSegmentCount = 0;
  }

#ifdef SUPPORT_RSC
  if (!adapter_config.is_rsc_ipv4_enabled()) {
    offload_config->Rsc.IPv4.Enabled = false;
  }

  if (!adapter_config.is_rsc_ipv6_enabled()) {
    offload_config->Rsc.IPv6.Enabled = false;
  }
#endif
}

NDIS_STATUS UpdateOffloadConfigFromEncapsulation(
    const NDIS_OFFLOAD& offload_capability,
    NDIS_OFFLOAD_ENCAPSULATION encapsulation, NDIS_HANDLE miniport_handle,
    NDIS_OFFLOAD* offload_config) {
  DEBUGP(GVNIC_INFO,
         "[%s] Try to apply NDIS_OFFLOAD_ENCAPSULATION TPv4 %d, IPv6 %d",
         __FUNCTION__, encapsulation.IPv4.Enabled, encapsulation.IPv6.Enabled);
  NDIS_OFFLOAD new_config = *offload_config;  // Make a copy of current config

  if (encapsulation.IPv4.Enabled == NDIS_OFFLOAD_SET_ON) {
    new_config.Checksum.IPv4Receive.TcpChecksum =
        new_config.Checksum.IPv4Receive.UdpChecksum =
            new_config.Checksum.IPv4Transmit.TcpChecksum =
                new_config.Checksum.IPv4Transmit.UdpChecksum =
                    NDIS_OFFLOAD_SUPPORTED;
    new_config.LsoV1.IPv4.Encapsulation = new_config.LsoV2.IPv4.Encapsulation =
        NDIS_ENCAPSULATION_IEEE_802_3;
  } else if (encapsulation.IPv4.Enabled == NDIS_OFFLOAD_SET_OFF) {
    new_config.Checksum.IPv4Receive.TcpChecksum =
        new_config.Checksum.IPv4Receive.UdpChecksum =
            new_config.Checksum.IPv4Transmit.TcpChecksum =
                new_config.Checksum.IPv4Transmit.UdpChecksum =
                    NDIS_OFFLOAD_NOT_SUPPORTED;
    new_config.LsoV1.IPv4.Encapsulation = new_config.LsoV2.IPv4.Encapsulation =
        NDIS_ENCAPSULATION_NOT_SUPPORTED;
  }

  if (encapsulation.IPv6.Enabled == NDIS_OFFLOAD_SET_ON) {
    new_config.Checksum.IPv6Receive.TcpChecksum =
        new_config.Checksum.IPv6Receive.UdpChecksum =
            new_config.Checksum.IPv6Transmit.TcpChecksum =
                new_config.Checksum.IPv6Transmit.UdpChecksum =
                    NDIS_OFFLOAD_SUPPORTED;
    new_config.LsoV2.IPv6.Encapsulation = NDIS_ENCAPSULATION_IEEE_802_3;
  } else if (encapsulation.IPv6.Enabled == NDIS_OFFLOAD_SET_OFF) {
    new_config.Checksum.IPv6Receive.TcpChecksum =
        new_config.Checksum.IPv6Receive.UdpChecksum =
            new_config.Checksum.IPv6Transmit.TcpChecksum =
                new_config.Checksum.IPv6Transmit.UdpChecksum =
                    NDIS_OFFLOAD_NOT_SUPPORTED;
    new_config.LsoV2.IPv6.Encapsulation = NDIS_ENCAPSULATION_NOT_SUPPORTED;
  }

  if (!ValidateOffloadConfig(new_config, offload_capability)) {
    DEBUGP(GVNIC_ERROR, "[%s] ERROR the offload request is invalid.",
           __FUNCTION__);
    LogOffloadSetting("Request Config", new_config);

    return NDIS_STATUS_INVALID_PARAMETER;
  }

  if (ApplyOffloadConfig(new_config, offload_config)) {
    SendOffloadStatusIndication(miniport_handle, *offload_config);
  }

  return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS UpdateOffloadConfigFromOffloadParameters(
    const NDIS_OFFLOAD& offload_capability,
    NDIS_OFFLOAD_PARAMETERS offload_parameters, NDIS_HANDLE miniport_handle,
    NDIS_OFFLOAD* offload_config) {
  NDIS_OFFLOAD new_config = *offload_config;  // Make a copy of current config
  NDIS_TCP_IP_CHECKSUM_OFFLOAD* new_checksum = &new_config.Checksum;

  new_checksum->IPv4Receive.IpChecksum =
      GetChecksumSetting(offload_parameters.IPv4Checksum, false,
                         new_checksum->IPv4Receive.IpChecksum);
  new_checksum->IPv4Receive.TcpChecksum =
      GetChecksumSetting(offload_parameters.TCPIPv4Checksum, false,
                         new_checksum->IPv4Receive.TcpChecksum);
  new_checksum->IPv4Receive.UdpChecksum =
      GetChecksumSetting(offload_parameters.UDPIPv4Checksum, false,
                         new_checksum->IPv4Receive.UdpChecksum);
  new_checksum->IPv4Transmit.IpChecksum =
      GetChecksumSetting(offload_parameters.IPv4Checksum, true,
                         new_checksum->IPv4Transmit.IpChecksum);
  new_checksum->IPv4Transmit.TcpChecksum =
      GetChecksumSetting(offload_parameters.TCPIPv4Checksum, true,
                         new_checksum->IPv4Transmit.TcpChecksum);
  new_checksum->IPv4Transmit.UdpChecksum =
      GetChecksumSetting(offload_parameters.UDPIPv4Checksum, true,
                         new_checksum->IPv4Transmit.UdpChecksum);

  new_checksum->IPv6Receive.TcpChecksum =
      GetChecksumSetting(offload_parameters.TCPIPv6Checksum, false,
                         new_checksum->IPv6Receive.TcpChecksum);
  new_checksum->IPv6Receive.UdpChecksum =
      GetChecksumSetting(offload_parameters.UDPIPv6Checksum, false,
                         new_checksum->IPv6Receive.UdpChecksum);
  new_checksum->IPv6Transmit.TcpChecksum =
      GetChecksumSetting(offload_parameters.TCPIPv6Checksum, true,
                         new_checksum->IPv6Transmit.TcpChecksum);
  new_checksum->IPv6Transmit.UdpChecksum =
      GetChecksumSetting(offload_parameters.UDPIPv6Checksum, true,
                         new_checksum->IPv6Transmit.UdpChecksum);

  if (offload_parameters.LsoV2IPv4 == NDIS_OFFLOAD_PARAMETERS_LSOV2_ENABLED ||
      offload_parameters.LsoV1 == NDIS_OFFLOAD_PARAMETERS_LSOV1_ENABLED) {
    new_config.LsoV1.IPv4.Encapsulation = new_config.LsoV2.IPv4.Encapsulation =
        NDIS_ENCAPSULATION_IEEE_802_3;
  } else if (offload_parameters.LsoV2IPv4 ==
                 NDIS_OFFLOAD_PARAMETERS_LSOV2_DISABLED ||
             offload_parameters.LsoV1 ==
                 NDIS_OFFLOAD_PARAMETERS_LSOV1_ENABLED) {
    new_config.LsoV1.IPv4.Encapsulation = new_config.LsoV2.IPv4.Encapsulation =
        NDIS_ENCAPSULATION_NOT_SUPPORTED;
  }

  if (offload_parameters.LsoV2IPv6 == NDIS_OFFLOAD_PARAMETERS_LSOV2_ENABLED) {
    new_config.LsoV2.IPv6.Encapsulation = NDIS_ENCAPSULATION_IEEE_802_3;
  } else if (offload_parameters.LsoV2IPv6 ==
             NDIS_OFFLOAD_PARAMETERS_LSOV2_DISABLED) {
    new_config.LsoV2.IPv6.Encapsulation = NDIS_ENCAPSULATION_NOT_SUPPORTED;
  }

#ifdef SUPPORT_RSC
  // RSC settings.
  if (offload_parameters.RscIPv4 == NDIS_OFFLOAD_PARAMETERS_RSC_DISABLED) {
    new_config.Rsc.IPv4.Enabled = false;
  } else if (offload_parameters.RscIPv4 ==
             NDIS_OFFLOAD_PARAMETERS_RSC_ENABLED) {
    new_config.Rsc.IPv4.Enabled = true;
  }

  if (offload_parameters.RscIPv6 == NDIS_OFFLOAD_PARAMETERS_RSC_DISABLED) {
    new_config.Rsc.IPv6.Enabled = false;
  } else if (offload_parameters.RscIPv6 ==
             NDIS_OFFLOAD_PARAMETERS_RSC_ENABLED) {
    new_config.Rsc.IPv6.Enabled = true;
  }
#endif

  if (!ValidateOffloadConfig(new_config, offload_capability)) {
    DEBUGP(GVNIC_ERROR, "[%s] ERROR the offload request is invalid.",
           __FUNCTION__);
    LogOffloadSetting("Request Config", new_config);
    return NDIS_STATUS_INVALID_PARAMETER;
  }

  if (ApplyOffloadConfig(new_config, offload_config)) {
    SendOffloadStatusIndication(miniport_handle, *offload_config);
  }

  return NDIS_STATUS_SUCCESS;
}

void LogOffloadSetting(const char* message, const NDIS_OFFLOAD& offload) {
  DEBUGP(GVNIC_INFO, "[%s] %s", __FUNCTION__, message);
  DEBUGP(GVNIC_INFO, "Checksum ipv4 TCP: %s, UDP: %s, IP: %s",
         GetOffloadSettingString(offload.Checksum.IPv4Transmit.TcpChecksum,
                                 offload.Checksum.IPv4Receive.TcpChecksum),
         GetOffloadSettingString(offload.Checksum.IPv4Transmit.UdpChecksum,
                                 offload.Checksum.IPv4Receive.UdpChecksum),
         GetOffloadSettingString(offload.Checksum.IPv4Transmit.IpChecksum,
                                 offload.Checksum.IPv4Receive.IpChecksum));
  DEBUGP(GVNIC_INFO, "Checksum ipv6 TCP: %s, UPD: %s",
         GetOffloadSettingString(offload.Checksum.IPv6Transmit.TcpChecksum,
                                 offload.Checksum.IPv6Receive.TcpChecksum),
         GetOffloadSettingString(offload.Checksum.IPv6Transmit.UdpChecksum,
                                 offload.Checksum.IPv6Receive.UdpChecksum));
  DEBUGP(GVNIC_INFO, "LSO v1 IPv4 enabled %d",
         offload.LsoV1.IPv4.Encapsulation == NDIS_ENCAPSULATION_IEEE_802_3);
  DEBUGP(GVNIC_INFO, "LSO v2 IPv4 enabled %d",
         offload.LsoV2.IPv4.Encapsulation == NDIS_ENCAPSULATION_IEEE_802_3);
  DEBUGP(GVNIC_INFO, "LSO v2 IPv6 enabled %d",
         offload.LsoV2.IPv6.Encapsulation == NDIS_ENCAPSULATION_IEEE_802_3);

#ifdef SUPPORT_RSC
  DEBUGP(GVNIC_INFO, "RSC IPv4 enabled %d", offload.Rsc.IPv4.Enabled);
  DEBUGP(GVNIC_INFO, "RSC IPv6 enabled %d", offload.Rsc.IPv6.Enabled);
#endif
}
