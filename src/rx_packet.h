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

#ifndef RX_PACKET_H_
#define RX_PACKET_H_

#include <ndis.h>

#include "abi.h"       // NOLINT: include directory
#include "netutils.h"  // NOLINT: include directory
#include "rx_ring_entry.h"  // NOLINT: include directory

// Since Eth Header is 14 bytes, Two bytes padding was added by device for
// data alignment.
constexpr int kPacketHeaderPadding = 2;

// Wrapper class for rx net packets.
// It does checksum validation.
__declspec(align(kCacheLineSize)) class RxPacket final {
 public:
  // Arguments:
  //  rx_ring_entry: RxRingEntry contains info about the packet.
  explicit RxPacket(const RxRingEntry& rx_ring_entry);

  // Set check sum info for the NET_BUFFER_LIST.
  // Please note that the method doesn't support calculating ipv6 check sum.
  void SetChecksumInfo();

  // Save hash_type, hash_function, hash_type to NET_BUFFER_LIST.
  void SetRssInfo(UINT32 rss_hash_value, UINT32 rss_hash_type,
                  UINT8 rss_hash_func);

#ifdef DBG
  // Calculate the correct rss hash value for verification.
  UINT32 CalculateRss(UINT32 rss_hash_type);
  void SetSecretKey(const UINT8* rss_secret_key);

  // Verifies that the packet is processed on the correct RSS processor.
  void SetIndirectionTable(UINT16 indirection_table_entry_count,
                           const PROCESSOR_NUMBER* indirection_table);
  ULONG GetExpectedRSSProcessor(UINT32 rss_hash_value);
#endif

  ETH_HEADER* eth_header() const { return eth_header_; }
  UINT packet_length() const { return packet_length_; }
  UINT64 queue_page_list_offset() { return queue_page_list_offset_; }

  bool is_ipv4() const { return is_ipv4_; }

  bool is_tcp() const { return is_tcp_; }
  bool is_udp() const { return is_udp_; }
  IPv4Header* ipv4_header() const {
    NT_ASSERT(is_ipv4_);
    return ipv4_header_;
  }
  TcpHeader* tcp_header() const {
    NT_ASSERT(is_ipv4_ && is_tcp_);
    return tcp_header_;
  }
  NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO checksum_info() const {
    return checksum_info_;
  }

  bool is_checksum_offload() const { return is_checksum_offload_; }
  bool is_rss_offload() const { return is_rss_offload_; }

  UINT32 rss_hash_value() const { return rss_hash_value_; }
  UINT32 rss_hash_type() const { return rss_hash_type_; }
  UINT8 rss_hash_func() const { return rss_hash_func_; }

  NET_BUFFER_LIST* net_buffer_list() { return net_buffer_list_; }

 private:
  UINT64 queue_page_list_offset_;
  UINT16 packet_flag_;

  // Checksum calculated by device:
  // It is the 16-bit 1's-complement sum computed over all packet bytes,
  // starting from the Ethernet payload (at offset 14).
  UINT16 partial_csum_;

  ETH_HEADER* eth_header_;
  IPv4Header* ipv4_header_;
  TcpHeader* tcp_header_;
  bool is_ipv4_;
  bool is_tcp_;
  bool is_udp_;

  bool is_checksum_offload_;
  bool is_rss_offload_;

  UINT32 rss_hash_value_;
  UINT32 rss_hash_type_;
  UINT8 rss_hash_func_;

  NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO checksum_info_;

  UINT packet_length_;
  NET_BUFFER_LIST* net_buffer_list_;

#ifdef DBG
  const UINT8* secret_key_;
  const PROCESSOR_NUMBER* indirection_table_;
  UINT16 indirection_table_entry_count_;
#endif

  // Return TCP/UDP validation checksum.
  UINT16 CalculateL4Checksum(UINT16 ip_header_len);
};

#endif  // RX_PACKET_H_
