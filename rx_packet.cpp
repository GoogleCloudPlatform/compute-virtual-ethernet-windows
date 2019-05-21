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

#include "rx_packet.h"  // NOLINT: include directory

#include <ndis.h>

#include "abi.h"            // NOLINT: include directory
#include "netutils.h"       // NOLINT: include directory
#include "rx_ring.h"        // NOLINT: include directory
#include "rx_ring_entry.h"  // NOLINT: include directory
#include "utils.h"          // NOLINT: include directory

namespace {
// Mask to get the mdl offset from data ring address.
constexpr UINT32 kMdlOffsetMask = PAGE_SIZE - 1;

UINT16 kExpectedSum = 0xffff;  // Expected one's complement sum for validation.

// Calculate one's complement sum following:
// https://tools.ietf.org/html/rfc1071
UINT16 ComputeOneComplementSum(void* buffer, size_t size) {
  UINT16* index_buffer = reinterpret_cast<UINT16*>(buffer);
  UINT32 sum = 0;

  while (size > 1) {
    sum += *index_buffer++;
    size -= sizeof(UINT16);
  }

  // Add left-over byte, if size is odd number.
  if (size > 0) {
    sum += *reinterpret_cast<UINT8*>(index_buffer);
  }

  // Folder 32-bit sum into 16 bits.
  while (sum >> 16) {
    // Add overflow bit into lower 16 bits int.
    sum = (sum & 0xffff) + (sum >> 16);
  }

  return static_cast<UINT16>(sum);
}

#if DBG
// the helper function for calculation rss hash value
UINT32 ComputeHash(const bool* input, const UINT8* secret_key,
                   UINT32 input_size) {
  UINT32 result = 0;

  // secret key has 40 separate key
  for (UINT32 i = 0; i < input_size; i++) {
    bool cur_bit = input[i];
    if (cur_bit) {
      int combined_int = 0;

      for (int j = 0; j < 32; j++) {
        combined_int <<= 1;
        combined_int |= (secret_key[(i + j) / 8] >> (7 - (i + j) % 8))
            & 0x00000001;
      }
      result ^= combined_int;
    }
  }
  return result;
}
#endif
}  // namespace

RxPacket::RxPacket(const RxRingEntry& rx_ring_entry)
    : queue_page_list_offset_(0),
      packet_flag_(0),
      eth_header_(nullptr),
      ipv4_header_(nullptr),
      tcp_header_(nullptr),
      partial_csum_(0),
      is_ipv4_(false),
      is_tcp_(false),
      is_udp_(false),
      is_checksum_offload_(false),
      is_rss_offload_(false),
      rss_hash_func_(0),
      rss_hash_type_(0),
      rss_hash_value_(0),
      checksum_info_({}),
      packet_length_(0) {
  packet_length_ = RtlUshortByteSwap(rx_ring_entry.descriptor->packet_length) -
                   kPacketHeaderPadding;
  queue_page_list_offset_ =
      RtlUlonglongByteSwap(rx_ring_entry.data->queue_page_list_offset);
  partial_csum_ = rx_ring_entry.descriptor->checksum;

  // Check whether the packet stays in first or second half of the page.
  UINT packet_idx = (queue_page_list_offset_ & kMdlOffsetMask) == 0 ? 0 : 1;
  eth_header_ = rx_ring_entry.eth_header[packet_idx];
  net_buffer_list_ = rx_ring_entry.net_buffer_lists[packet_idx];

  packet_flag_ = RtlUshortByteSwap(rx_ring_entry.descriptor->flags_sequence) >>
                 kRxSequenceLength;
  if (packet_flag_ & kRxDescriptorFlagIPv4) {
    is_ipv4_ = true;
    ipv4_header_ = rx_ring_entry.ipv4_header[packet_idx];

    is_tcp_ = !!(packet_flag_ & kRxDescriptorFlagTcp);
    is_udp_ = !!(packet_flag_ & kRxDescriptorFlagUdp);

    if (is_tcp_) {
      tcp_header_ = reinterpret_cast<TcpHeader*>(OffsetToPointer(
          ipv4_header_, ipv4_header_->internet_header_length * 4));
    }
  }
}

void RxPacket::SetChecksumInfo() {
  is_checksum_offload_ = true;
  if (is_ipv4_) {
    UINT16 ip_header_len = ipv4_header_->internet_header_length * 4;
    UINT16 ip_csum = ComputeOneComplementSum(ipv4_header_, ip_header_len);
    if (ip_csum == kExpectedSum) {
      checksum_info_.Receive.IpChecksumSucceeded = true;
    } else {
      checksum_info_.Receive.IpChecksumFailed = true;
    }

    if (partial_csum_ && (is_tcp_ || is_udp_)) {
      UINT16 l4_csum = CalculateL4Checksum(ip_header_len);

      if (l4_csum == kExpectedSum) {
        if (is_tcp_) {
          checksum_info_.Receive.TcpChecksumSucceeded = true;
        } else {
          checksum_info_.Receive.UdpChecksumSucceeded = true;
        }
      } else {
        if (is_tcp_) {
          checksum_info_.Receive.TcpChecksumFailed = true;
        } else {
          checksum_info_.Receive.UdpChecksumFailed = true;
        }
      }
    }
  }
  LogRxChecksum(checksum_info_, packet_flag_);
}

#if DBG
UINT32 ConvertUINT32LittleEnd(UINT32 address) {
  return address >> 24 & 0xff | address >> 8 & 0xff00 |
       address << 8 & 0xff0000 | address << 24 & 0xff000000;
}


UINT16 ConvertUINT16LittleEnd(UINT16 address) {
  return address >> 8 & 0xff | address << 8 & 0xff00;
}


UINT32 RxPacket::CalculateRss(UINT32 rss_hash_type) {
  bool input[96];
  UINT32 source_address = ConvertUINT32LittleEnd(ipv4_header_->source_address);
  UINT32 dest_address = ConvertUINT32LittleEnd(ipv4_header_->dest_address);

  for (int i = 0; i < 32; i++) {
    input[64 - i - 1] = dest_address & 0x01;
    dest_address >>= 1;
    input[32 - i - 1] = source_address & 0x01;
    source_address >>= 1;
  }

  UINT16 source_port = 0;
  UINT16 dest_port = 0;
  UINT32 input_size = 64;

  // need to extract port information with tcp and udp.
  if ((rss_hash_type & NDIS_HASH_TCP_IPV4) && is_tcp_) {
    source_port = ConvertUINT16LittleEnd(tcp_header_->source_port);
    dest_port = ConvertUINT16LittleEnd(tcp_header_->dest_port);

    for (int i = 0; i < 16; i++) {
      input[96 - i - 1] = dest_port & 0x01;
      dest_port >>= 1;
      input[80 - i - 1] = source_port & 0x01;
      source_port >>= 1;
    }
    input_size = 96;
  } else if ((rss_hash_type & NDIS_HASH_UDP_IPV4) && is_udp_) {
    UdpHeader* udp_header_ = reinterpret_cast<UdpHeader*>(
      OffsetToPointer(ipv4_header_, sizeof(IPv4Header)));
    source_port = ConvertUINT16LittleEnd(udp_header_->source_port);
    dest_port = ConvertUINT16LittleEnd(udp_header_->dest_port);

    for (int i = 0; i < 16; i++) {
      input[96 - i - 1] = dest_port & 0x01;
      dest_port >>= 1;
      input[80 - i - 1] = source_port & 0x01;
      source_port >>= 1;
    }
    input_size = 96;
  }

  return ComputeHash(input, secret_key_, input_size);
}


void RxPacket::SetSecretKey(const UINT8* rss_secret_key) {
  secret_key_ = rss_secret_key;
}
#endif

void RxPacket::SetRssInfo(UINT32 rss_hash_value, UINT32 rss_hash_type,
                          UINT8 rss_hash_func) {
  if (is_ipv4_) {
#if DBG
    UINT32 expect_rss_hash_value = CalculateRss(rss_hash_type);
    NT_ASSERT(rss_hash_value == expect_rss_hash_value);
#endif
    rss_hash_value_ = rss_hash_value;
    rss_hash_type_ = rss_hash_type;
    rss_hash_func_ = rss_hash_func;
    is_rss_offload_ = true;
  }
}

// TCP/UDP csum = pseudo_header + tcp/udp header + data_body
// Gvnic csum = ip_header + tcp/udp header + data_body
// Since csum of IP header should be zero, to get real TCP/UDP csum we
// only need to calculate:
//    pseudo_header_csum + gvnic_csum.
UINT16 RxPacket::CalculateL4Checksum(UINT16 ip_header_len) {
  IPv4PseudoHeader pseudo_header = {};
  pseudo_header.source_address = ipv4_header_->source_address;
  pseudo_header.dest_address = ipv4_header_->dest_address;
  pseudo_header.protocol = ipv4_header_->protocol;
  // Need to follow network packet bit order.
  pseudo_header.length =
      RtlUshortByteSwap(packet_length_ - kEthHeaderSize - ip_header_len);

  UINT16 pseudo_header_csum =
      ComputeOneComplementSum(&pseudo_header, sizeof(IPv4PseudoHeader));

  UINT32 combined_csum = (pseudo_header_csum << 16) | partial_csum_;
  return ComputeOneComplementSum(&combined_csum, sizeof(UINT32));
}
