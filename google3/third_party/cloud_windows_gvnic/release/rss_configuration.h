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

#ifndef RSS_CONFIGURATION_H_
#define RSS_CONFIGURATION_H_

#include <ndis.h>


// hash_type_ will stay in the range of 0x00FFFF00, which needs to be right
// shift 8 bits to fit the input format of the device.
static constexpr UINT8 kRssHashTypeShift = 8;


// Class for store adapter RSS configuration.
class RSSConfiguration final {
 public:
  static NDIS_RECEIVE_SCALE_CAPABILITIES GetCapabilities(UINT32 num_msi_vectors,
                                                         UINT32 num_rx_queue);

  RSSConfiguration()
      : is_enabled_(false),
        is_supported_(false),
        hash_func_(0),
        hash_type_(0),
        base_cpu_number_(0),
        indirection_table_entry_count_(0) {}
  ~RSSConfiguration() = default;

  // Default copy and assignment.
  RSSConfiguration(const RSSConfiguration&) = default;
  RSSConfiguration& operator=(const RSSConfiguration&) = default;

  // Init rss settings.
  // Params:
  //  is_supported - whether rss is configured as supported.
  void Init(bool is_supported);

  // Reset all configurations back to default.
  void Reset();

  // Verified the NDIS_RECEIVE_SCALE_PARAMETERS and parse/save the setting.
  // Params:
  //  - rss_params[in]: pointer to the NDIS_RECEIVE_SCALE_PARAMETERS.
  //  - param_length[in]: the length of the total rss_param buffer.
  //  - num_bytes_read[out]: number of bytes consumed by the function.
  NDIS_STATUS
  ApplyReceiveScaleParameters(const NDIS_RECEIVE_SCALE_PARAMETERS* rss_params,
                              UINT32 param_length, UINT32* num_byte_read);

  bool is_enabled() const { return is_enabled_; }
  UINT32 hash_type() const { return hash_type_; }
  UINT8 hash_func() const { return hash_func_; }
  UINT16 hash_secret_key_size() const { return kHashKeySize; }
  const UINT8* hash_secret_key() const { return hash_secret_key_; }
  UINT16 indirection_table_size() const {
    return indirection_table_entry_count_;
  }
  const PROCESSOR_NUMBER* indirection_table() const {
    return indirection_table_;
  }

  // Helper function to log all settings.
  void DumpSettings();

 private:
  // Only support Toeplitz hashing and the key size is fixed. For more about
  // Teoplitz hashing:
  // https://docs.microsoft.com/en-us/windows-hardware/drivers/network/rss-hashing-functions
  static constexpr UINT16 kHashKeySize = 40;

  // Each entry is PROCESSOR_NUMBER struct.
  static constexpr UINT kMaxIndirectionTableSize =
      NDIS_RSS_INDIRECTION_TABLE_MAX_SIZE_REVISION_2 / sizeof(PROCESSOR_NUMBER);

  NDIS_STATUS ValidateRSSParamters(
      const NDIS_RECEIVE_SCALE_PARAMETERS* rss_params, UINT32 param_length);

  // Whether rss is supported.
  bool is_supported_;

  bool is_enabled_;
  UINT16 base_cpu_number_;

  UINT8 hash_func_;
  UINT32 hash_type_;

  // Hash key used in the hash function.
  UINT8 hash_secret_key_[kHashKeySize];

  // Total number of entries in the indirection table.
  UINT16 indirection_table_entry_count_;
  // Indirection table, mapping of hash_value -> PROCESSOR_NUMBER
  PROCESSOR_NUMBER indirection_table_[kMaxIndirectionTableSize];
};

#endif  // RSS_CONFIGURATION_H_
