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

#include "tx_net_buffer.h"  // NOLINT: include directory

#include <ndis.h>

#include "netutils.h"   // NOLINT: include directory
#include "utils.h"      // NOLINT: include directory

namespace {
const UINT8 kTcpChecksumOffset = FIELD_OFFSET(TcpHeader, checksum);
const UINT8 kUdpChecksumOffset = FIELD_OFFSET(UdpHeader, checksum);
}  // namespace

TxNetBuffer::TxNetBuffer(
    const NET_BUFFER* net_buffer,
    const NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO& csum_info,
    const NDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO& lso_info,
    EthHeaderLength eth_header_len)
    : net_buffer_(nullptr),
      eth_header_(nullptr),
      is_checksum_offload_(false),
      checksum_info_(csum_info),
      lso_info_(lso_info),
      is_lso_(false),
      eth_header_len_(eth_header_len) {
  net_buffer_ = net_buffer;
  data_length_ = NET_BUFFER_DATA_LENGTH(net_buffer_);

  void* mdl_addr = MmGetSystemAddressForMdlSafe(
      NET_BUFFER_CURRENT_MDL(net_buffer), LowPagePriority);

  if (mdl_addr == nullptr) {
    // Map memory failed. Leave all value as default.
    return;
  }

  int offset = NET_BUFFER_CURRENT_MDL_OFFSET(net_buffer);
  void* header_addr = OffsetToPointer(mdl_addr, offset);
  eth_header_ = reinterpret_cast<ETH_HEADER*>(header_addr);

  if (checksum_info_.Transmit.IsIPv4 || checksum_info_.Transmit.IsIPv6) {
    if (checksum_info_.Transmit.TcpChecksum ||
        checksum_info_.Transmit.UdpChecksum) {
      is_checksum_offload_ = true;
    }
  }

  if (lso_info_.Value != nullptr) {
    is_lso_ = true;
  }
}

UINT8 TxNetBuffer::GetChecksumOffsetWithinL4() const {
  if (checksum_info_.Transmit.TcpChecksum || is_lso_) {
    return kTcpChecksumOffset;
  }

  if (checksum_info_.Transmit.UdpChecksum) {
    return kUdpChecksumOffset;
  }

  return 0u;
}

UINT8 TxNetBuffer::GetL3Offset() const {
  NT_ASSERT(is_lso_);
  if (is_lso_) {
    if (lso_info_.LsoV2Transmit.IPVersion == NDIS_TCP_LARGE_SEND_OFFLOAD_IPv4) {
      return static_cast<UINT8>(eth_header_len_.IPv4);
    }

    if (lso_info_.LsoV2Transmit.IPVersion == NDIS_TCP_LARGE_SEND_OFFLOAD_IPv6) {
      return static_cast<UINT8>(eth_header_len_.IPv6);
    }
  }

  return 0u;
}

UINT8 TxNetBuffer::GetL4Offset() const {
  if (is_lso_) {
    return lso_info_.LsoV2Transmit.TcpHeaderOffset;
  }

  if (checksum_info_.Transmit.TcpChecksum) {
    return checksum_info_.Transmit.TcpHeaderOffset;
  }

  if (checksum_info_.Transmit.IsIPv4) {
    return GetL4OffsetFromIPv4();
  }

  if (checksum_info_.Transmit.IsIPv6) {
    return GetL4OffsetFromIPv6();
  }

  return 0u;
}

UINT8 TxNetBuffer::GetL4OffsetFromIPv4() const {
  IPv4Header* ip_header = reinterpret_cast<IPv4Header*>(
      OffsetToPointer(eth_header_, eth_header_len_.IPv4));
  // Internet header length is in 32 bit word count.
  return static_cast<UINT8>(eth_header_len_.IPv4 +
                            ip_header->internet_header_length * 4);
}

UINT8 TxNetBuffer::GetL4OffsetFromIPv6() const {
  return static_cast<UINT8>(eth_header_len_.IPv6 + kIPv6HeaderSize);
}
