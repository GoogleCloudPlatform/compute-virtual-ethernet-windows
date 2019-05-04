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

#include "adapter_statistics.h"  // NOLINT: include directory

#include <ndis.h>

#include "netutils.h"           // NOLINT: include directory
#include "spin_lock_context.h"  // NOLINT: include directory
#include "tx_net_buffer.h"      // NOLINT: include directory
#include "utils.h"              // NOLINT: include directory

namespace {
// NDIS 6.0 must support all statistics.
// See SupportedStatistics section on:
// https://msdn.microsoft.com/en-us/library/windows/hardware/ff565923(v=vs.85).aspx
constexpr ULONG kSupportedStatistics =
    0 | NDIS_STATISTICS_DIRECTED_FRAMES_RCV_SUPPORTED |
    NDIS_STATISTICS_MULTICAST_FRAMES_RCV_SUPPORTED |
    NDIS_STATISTICS_BROADCAST_FRAMES_RCV_SUPPORTED |
    NDIS_STATISTICS_BYTES_RCV_SUPPORTED |
    NDIS_STATISTICS_RCV_DISCARDS_SUPPORTED |
    NDIS_STATISTICS_RCV_ERROR_SUPPORTED |
    NDIS_STATISTICS_DIRECTED_FRAMES_XMIT_SUPPORTED |
    NDIS_STATISTICS_MULTICAST_FRAMES_XMIT_SUPPORTED |
    NDIS_STATISTICS_BROADCAST_FRAMES_XMIT_SUPPORTED |
    NDIS_STATISTICS_BYTES_XMIT_SUPPORTED |
    NDIS_STATISTICS_XMIT_ERROR_SUPPORTED |
    NDIS_STATISTICS_XMIT_DISCARDS_SUPPORTED |
    NDIS_STATISTICS_DIRECTED_BYTES_RCV_SUPPORTED |
    NDIS_STATISTICS_MULTICAST_BYTES_RCV_SUPPORTED |
    NDIS_STATISTICS_BROADCAST_BYTES_RCV_SUPPORTED |
    NDIS_STATISTICS_DIRECTED_BYTES_XMIT_SUPPORTED |
    NDIS_STATISTICS_DIRECTED_BYTES_XMIT_SUPPORTED |
    NDIS_STATISTICS_BROADCAST_BYTES_XMIT_SUPPORTED;

}  // namespace

void AdapterStatistics::AddSentPacket(UINT byte_send,
                                      const ETH_HEADER* eth_header) {
  statistics_info_.ifHCOutOctets += byte_send;
  if (ETH_IS_MULTICAST(eth_header)) {
    statistics_info_.ifHCOutMulticastOctets += byte_send;
    statistics_info_.ifHCOutMulticastPkts++;
  } else if (ETH_IS_BROADCAST(eth_header)) {
    statistics_info_.ifHCOutBroadcastOctets += byte_send;
    statistics_info_.ifHCOutBroadcastPkts++;
  } else {
    statistics_info_.ifHCOutUcastOctets += byte_send;
    statistics_info_.ifHCOutUcastPkts++;
  }
}

void AdapterStatistics::AddReceivedPacket(UINT byte_receive,
                                          const ETH_HEADER* eth_header) {
  statistics_info_.ifHCInOctets += byte_receive;
  if (ETH_IS_MULTICAST(eth_header)) {
    statistics_info_.ifHCInMulticastOctets += byte_receive;
    statistics_info_.ifHCInMulticastPkts++;
  } else if (ETH_IS_BROADCAST(eth_header)) {
    statistics_info_.ifHCInBroadcastOctets += byte_receive;
    statistics_info_.ifHCInBroadcastPkts++;
  } else {
    statistics_info_.ifHCInUcastOctets += byte_receive;
    statistics_info_.ifHCInUcastPkts++;
  }
}

void AdapterStatistics::Init() {
  PAGED_CODE();
  NdisZeroMemory(&statistics_info_, sizeof(statistics_info_));
  statistics_info_.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
  statistics_info_.Header.Revision = NDIS_STATISTICS_INFO_REVISION_1;
  statistics_info_.Header.Size = NDIS_SIZEOF_STATISTICS_INFO_REVISION_1;
  statistics_info_.SupportedStatistics = kSupportedStatistics;
}

void AdapterStatistics::Release() {}
