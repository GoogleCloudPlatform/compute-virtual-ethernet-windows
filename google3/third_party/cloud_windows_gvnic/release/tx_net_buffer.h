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

#ifndef TX_NET_BUFFER_
#define TX_NET_BUFFER_

#include <ndis.h>
#include "netutils.h"            // NOLINT: include directory
#include "tx_net_buffer_list.h"  // NOLINT: include directory

// A wrapper class of NET_BUFFER provides interfaces required for processing
// the packet.
class TxNetBuffer final {
 public:
  // TxNetBuffer doesn't own net_buffer object and won't try to modify/free
  // the memory.
  explicit TxNetBuffer(
      const NET_BUFFER* net_buffer,
      const NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO& csum_info,
      const NDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO& lso_info,
      EthHeaderLength eth_header_len_);

  // Not copyable or movable.
  TxNetBuffer(const TxNetBuffer&) = delete;
  TxNetBuffer& operator=(const TxNetBuffer&) = delete;

  bool is_checksum_offload() const { return is_checksum_offload_; }
  bool is_lso() const { return is_lso_; }
  const ETH_HEADER* eth_header() const { return eth_header_; }
  int data_length() const { return data_length_; }
  UINT16 max_segment_size() const {
    NT_ASSERT(is_lso_);
    return lso_info_.LsoV2Transmit.MSS;
  }

  bool is_lso_ipv6() const {
    NT_ASSERT(is_lso_);
    return lso_info_.LsoV2Transmit.IPVersion ==
           NDIS_TCP_LARGE_SEND_OFFLOAD_IPv6;
  }

  // Return offset for checksum field within the l4 packets.
  // Only support TCP and UDP. Return 0 for all other types.
  UINT8 GetChecksumOffsetWithinL4() const;

  // Return the offset to the start of the IP payload.
  // Only support for IPv4 and IPv6, return 0 for other l3 type.
  UINT8 GetL4Offset() const;

  // Return the offset to the start of the Ether payload.
  UINT8 GetL3Offset() const;

 private:
  UINT8 GetL4OffsetFromIPv4() const;
  UINT8 GetL4OffsetFromIPv6() const;

  const NET_BUFFER* net_buffer_;
  int data_length_;
  ETH_HEADER* eth_header_;
  NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO checksum_info_;
  bool is_checksum_offload_;
  NDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO lso_info_;
  bool is_lso_;

  EthHeaderLength eth_header_len_;
};
#endif  // TX_NET_BUFFER_
