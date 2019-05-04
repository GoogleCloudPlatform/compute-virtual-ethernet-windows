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

#ifndef ADAPTER_STATISTICS_H_
#define ADAPTER_STATISTICS_H_

#include <ndis.h>

#include "abi.h"            // NOLINT: include directory
#include "tx_net_buffer.h"  // NOLINT: include directory

// Class to storing statistics for the adapter.
__declspec(align(kCacheLineSize)) class AdapterStatistics final {
 public:
  AdapterStatistics() = default;
  ~AdapterStatistics() = default;

  // Not copyable or movable
  AdapterStatistics(const AdapterStatistics&) = delete;
  AdapterStatistics& operator=(const AdapterStatistics&) = delete;

  // Return supported statistics for NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES.
  ULONG supported_statistics() const {
    return statistics_info_.SupportedStatistics;
  }

  UINT64 GetTransmitPacketCount() const {
    return statistics_info_.ifHCOutUcastPkts +
      statistics_info_.ifHCOutMulticastPkts +
      statistics_info_.ifHCOutBroadcastPkts;
  }

  UINT64 GetReceivePacketCount() const {
    return statistics_info_.ifHCInUcastPkts +
      statistics_info_.ifHCInMulticastPkts +
      statistics_info_.ifHCInBroadcastPkts;
  }

  void AddSentPacket(UINT byte_send, const ETH_HEADER* eth_header);

  void AddReceivedPacket(UINT byte_receive, const ETH_HEADER* eth_header);

  void Init();
  void Release();
  const NDIS_STATISTICS_INFO& info() const { return statistics_info_; }

 private:
  NDIS_STATISTICS_INFO statistics_info_;
};

#endif  // ADAPTER_STATISTICS_H_
