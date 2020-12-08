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

#ifndef ADAPTER_CONFIGURATION_H_
#define ADAPTER_CONFIGURATION_H_

#include "netutils.h"  // NOLINT: include directory

struct ConfigurationEntry {
  const char* name;  // String value of registry key.
  UINT32 value;      // Value of the configuration entry.
  UINT32 min_limit;  // Min limit of the value.
  UINT32 max_limit;  // Max limit of the value.
};

// Class for reading registry configuration.
class AdapterConfiguration final {
 public:
  AdapterConfiguration() : is_mac_configured_(false) {}
  ~AdapterConfiguration() = default;

  // Not copyable or movable
  AdapterConfiguration(const AdapterConfiguration&) = delete;
  AdapterConfiguration& operator=(const AdapterConfiguration&) = delete;

  // Initialize all configurations by default value and user set value from
  // registry.
  void Initialize(NDIS_HANDLE miniport_handle);

  UINT32 mtu() const { return mtu_.value; }
  const UCHAR* mac() const { return mac_; }
  bool is_mac_configured() const { return is_mac_configured_; }
  bool is_tx_tcp_checksum_offload_ipv4_enabled() const;
  bool is_tx_tcp_checksum_offload_ipv6_enabled() const;
  bool is_rx_tcp_checksum_offload_ipv4_enabled() const;
  bool is_rx_tcp_checksum_offload_ipv6_enabled() const;
  bool is_tx_udp_checksum_offload_ipv4_enabled() const;
  bool is_tx_udp_checksum_offload_ipv6_enabled() const;
  bool is_rx_udp_checksum_offload_ipv4_enabled() const;
  bool is_rx_udp_checksum_offload_ipv6_enabled() const;
  bool is_lso_v2_ipv4_enabled() const { return lso_v2_ipv4_.value == 1; }
  bool is_lso_v2_ipv6_enabled() const { return lso_v2_ipv6_.value == 1; }
  bool is_rss_enabled() const { return rss_.value == 1; }
  bool is_rsc_ipv4_enabled() const { return rsc_ipv4_.value == 1; }
  bool is_rsc_ipv6_enabled() const { return rsc_ipv6_.value == 1; }
  bool allow_raw_addressing() const { return allow_raw_addressing_.value == 1; }
  UINT32 num_tx_queue() const { return num_tx_queue_.value; }
  UINT32 num_rx_queue() const { return num_rx_queue_.value; }

 private:
  // Load the default value for all configuration entries.
  void LoadDefaultValue();

  ConfigurationEntry mtu_;
  ConfigurationEntry tcp_checksum_offload_ipv4_;
  ConfigurationEntry tcp_checksum_offload_ipv6_;
  ConfigurationEntry udp_checksum_offload_ipv4_;
  ConfigurationEntry udp_checksum_offload_ipv6_;
  ConfigurationEntry lso_v2_ipv4_;
  ConfigurationEntry lso_v2_ipv6_;
  ConfigurationEntry num_tx_queue_;
  ConfigurationEntry num_rx_queue_;
  ConfigurationEntry rss_;
  ConfigurationEntry rsc_ipv4_;
  ConfigurationEntry rsc_ipv6_;
  ConfigurationEntry allow_raw_addressing_;

  bool is_mac_configured_;
  UCHAR mac_[kEthAddrLen];
};

#endif  // ADAPTER_CONFIGURATION_H_
