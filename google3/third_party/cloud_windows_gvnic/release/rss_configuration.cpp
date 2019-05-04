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

#include "rss_configuration.h"  // NOLINT: include directory

#include <ndis.h>

#include "trace.h"  // NOLINT: include directory
#include "utils.h"  // NOLINT: include directory

#include "rss_configuration.tmh"  // NOLINT: trace message header

namespace {
bool IsPowerOfTwo(UINT32 num) { return (num != 0) && ((num & (num - 1)) == 0); }

}  // namespace

NDIS_RECEIVE_SCALE_CAPABILITIES
RSSConfiguration::GetCapabilities(UINT32 num_msi_vectors, UINT32 num_rx_queue) {
  NDIS_RECEIVE_SCALE_CAPABILITIES capabilities = {};
  capabilities.Header.Type = NDIS_OBJECT_TYPE_RSS_CAPABILITIES;
#if (NDIS_SUPPORT_NDIS630)
  capabilities.Header.Revision = NDIS_RECEIVE_SCALE_CAPABILITIES_REVISION_2;
  capabilities.Header.Size = NDIS_SIZEOF_RECEIVE_SCALE_CAPABILITIES_REVISION_2;
#else
  capabilities.Header.Revision = NDIS_RECEIVE_SCALE_CAPABILITIES_REVISION_1;
  capabilities.Header.Size = NDIS_SIZEOF_RECEIVE_SCALE_CAPABILITIES_REVISION_1;
#endif

  capabilities.CapabilitiesFlags =
      NDIS_RSS_CAPS_MESSAGE_SIGNALED_INTERRUPTS |
      NDIS_RSS_CAPS_CLASSIFICATION_AT_ISR |
      NDIS_RSS_CAPS_CLASSIFICATION_AT_DPC | NDIS_RSS_CAPS_HASH_TYPE_TCP_IPV4 |
      NDIS_RSS_CAPS_HASH_TYPE_TCP_IPV6 | NDIS_RSS_CAPS_HASH_TYPE_TCP_IPV6_EX |
      NDIS_RSS_CAPS_HASH_TYPE_UDP_IPV4 | NDIS_RSS_CAPS_HASH_TYPE_UDP_IPV6 |
      NDIS_RSS_CAPS_HASH_TYPE_UDP_IPV6_EX | NdisHashFunctionToeplitz;

  capabilities.NumberOfInterruptMessages = num_msi_vectors;
  capabilities.NumberOfReceiveQueues = num_rx_queue;
#if (NDIS_SUPPORT_NDIS630)
  capabilities.NumberOfIndirectionTableEntries = kMaxIndirectionTableSize;
#endif

  return capabilities;
}

void RSSConfiguration::Init(bool is_supported) {
  Reset();
  is_supported_ = is_supported;
}

void RSSConfiguration::Reset() {
  is_enabled_ = false;
  hash_func_ = 0;
  hash_type_ = 0;
  base_cpu_number_ = 0;
  indirection_table_entry_count_ = 0;
  NdisZeroMemory(hash_secret_key_, kHashKeySize * sizeof(UINT8));
  NdisZeroMemory(indirection_table_,
                 kMaxIndirectionTableSize * sizeof(PROCESSOR_NUMBER));
}

NDIS_STATUS RSSConfiguration::ApplyReceiveScaleParameters(
    const NDIS_RECEIVE_SCALE_PARAMETERS* rss_params, UINT32 param_length,
    UINT32* num_byte_read) {
  DEBUGP(GVNIC_INFO, "[%s] rss param flag: %#x", __FUNCTION__,
         rss_params->Flags);
  if (!is_supported_) {
    return NDIS_STATUS_NOT_SUPPORTED;
  }

  NDIS_STATUS status = ValidateRSSParamters(rss_params, param_length);

  if (status != NDIS_STATUS_SUCCESS) {
    return status;
  }

  *num_byte_read = 0;

  // Adjust enable flag.
  if ((rss_params->Flags & NDIS_RSS_PARAM_FLAG_DISABLE_RSS) ||
      rss_params->HashInformation == 0) {
    Reset();
    return NDIS_STATUS_SUCCESS;
  }

  is_enabled_ = true;

  // Apply hash info change.
  if (!(rss_params->Flags & NDIS_RSS_PARAM_FLAG_HASH_INFO_UNCHANGED)) {
    hash_func_ = NDIS_RSS_HASH_FUNC_FROM_HASH_INFO(rss_params->HashInformation);
    NT_ASSERT(hash_func_ == 1);

    hash_type_ = NDIS_RSS_HASH_TYPE_FROM_HASH_INFO(rss_params->HashInformation);
  }

  // Apply hash key change.
  if (!(rss_params->Flags & NDIS_RSS_PARAM_FLAG_HASH_KEY_UNCHANGED)) {
    NdisMoveMemory(
        hash_secret_key_,
        OffsetToPointer(const_cast<NDIS_RECEIVE_SCALE_PARAMETERS*>(rss_params),
                        rss_params->HashSecretKeyOffset),
        rss_params->HashSecretKeySize);

    *num_byte_read += rss_params->HashSecretKeySize;
  }

  // Apply indirection table change.
  if (!(rss_params->Flags & NDIS_RSS_PARAM_FLAG_ITABLE_UNCHANGED)) {
    indirection_table_entry_count_ =
        rss_params->IndirectionTableSize / sizeof(PROCESSOR_NUMBER);
    NdisMoveMemory(
        indirection_table_,
        OffsetToPointer(const_cast<NDIS_RECEIVE_SCALE_PARAMETERS*>(rss_params),
                        rss_params->IndirectionTableOffset),
        rss_params->IndirectionTableSize);

    *num_byte_read += rss_params->IndirectionTableSize;

    // Don't support NUMA. Skip processor group entries.
    *num_byte_read += rss_params->NumberOfProcessorMasks *
                      rss_params->ProcessorMasksEntrySize;
  }

  // Apply base cpu change.
  if (!(rss_params->Flags & NDIS_RSS_PARAM_FLAG_BASE_CPU_UNCHANGED)) {
    base_cpu_number_ = rss_params->BaseCpuNumber;
  }

  *num_byte_read += sizeof(NDIS_RECEIVE_SCALE_PARAMETERS);

  return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS RSSConfiguration::ValidateRSSParamters(
    const NDIS_RECEIVE_SCALE_PARAMETERS* rss_params, UINT32 param_length) {
  if (param_length < sizeof(NDIS_RECEIVE_SCALE_PARAMETERS)) {
    return NDIS_STATUS_INVALID_LENGTH;
  }

  if (rss_params->Flags & NDIS_RSS_PARAM_FLAG_DISABLE_RSS) {
    return NDIS_STATUS_SUCCESS;
  } else {
    // Need hash inform to turn on rss.
    if (rss_params->HashInformation == 0) {
      return NDIS_STATUS_INVALID_PARAMETER;
    }
  }

  // Verify indirection table settings.
  if (!(rss_params->Flags & NDIS_RSS_PARAM_FLAG_ITABLE_UNCHANGED)) {
    if (param_length <
        rss_params->IndirectionTableOffset + rss_params->IndirectionTableSize) {
      return NDIS_STATUS_INVALID_LENGTH;
    }

    UINT32 number_table_entries =
        rss_params->IndirectionTableSize / sizeof(PROCESSOR_NUMBER);
    if (!IsPowerOfTwo(number_table_entries)) {
      return NDIS_STATUS_INVALID_PARAMETER;
    }
  }

  // Verify Hash key.
  if (!(rss_params->Flags & NDIS_RSS_PARAM_FLAG_HASH_KEY_UNCHANGED)) {
    if (param_length <
        rss_params->HashSecretKeyOffset + rss_params->HashSecretKeySize) {
      return NDIS_STATUS_INVALID_LENGTH;
    }

    if (rss_params->HashSecretKeySize != kHashKeySize) {
      return NDIS_STATUS_INVALID_PARAMETER;
    }
  }

  // Verify process mask.
  UINT32 process_mask_size =
      rss_params->NumberOfProcessorMasks * rss_params->ProcessorMasksEntrySize;
  if (param_length < rss_params->ProcessorMasksOffset + process_mask_size) {
    return NDIS_STATUS_INVALID_LENGTH;
  }

  return NDIS_STATUS_SUCCESS;
}

void RSSConfiguration::DumpSettings() {
  DEBUGP(GVNIC_INFO, "[%s] enabled: %d", __FUNCTION__, is_enabled_);
  DEBUGP(GVNIC_INFO, "[%s] base_cpu_num: %d", __FUNCTION__, base_cpu_number_);
  DEBUGP(GVNIC_INFO, "[%s] hash_type: %#x", __FUNCTION__, hash_type_);
  DEBUGP(GVNIC_INFO, "[%s] hash_function: %#x", __FUNCTION__, hash_func_);

  DEBUGP(GVNIC_INFO, "[%s] indirection_table_len : %u", __FUNCTION__,
         indirection_table_entry_count_);
  for (UINT16 i = 0; i < indirection_table_entry_count_; i++) {
    DEBUGP(GVNIC_INFO, "[%s] indirection_table[%u] -> %u", __FUNCTION__, i,
           indirection_table_[i].Number);
  }
}
