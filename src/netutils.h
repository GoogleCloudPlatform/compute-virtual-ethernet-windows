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

#ifndef NET_UTILS_H_
#define NET_UTILS_H_

#include <ndis.h>

// Struct to store Ethernet header from OS.
struct EthHeaderLength {
  UINT32 IPv4;
  UINT32 IPv6;
};

constexpr int kEthAddrLen = 6;

#include <pshpack1.h>
// Struct for Ethernet header
struct ETH_HEADER {
  UCHAR dest_addr[kEthAddrLen];
  UCHAR src_addr[kEthAddrLen];
  USHORT eth_type;
};
static_assert(sizeof(ETH_HEADER) == 14, "Size of ETH_HEADER != 14");

// IP Header RFC 791: https://tools.ietf.org/html/rfc791#section-3.1
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |Version|  IHL  |Type of Service|          Total Length         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         Identification        |Flags|      Fragment Offset    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Time to Live |    Protocol   |         Header Checksum       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Source Address                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Destination Address                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Options                    |    Padding    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
struct IPv4Header {
  UINT8 internet_header_length : 4;
  UINT8 version : 4;
  UINT8 type_of_service;
  UINT16 total_length;
  UINT16 identification;
  UINT16 fragment_offset : 13;
  UINT16 flags : 3;
  UINT8 time_to_live;
  UINT8 protocol;
  UINT16 header_checksum;
  UINT32 source_address;
  UINT32 dest_address;
};
static_assert(sizeof(IPv4Header) == 20, "Size of IPv4Header != 20");

// Pseudo header used to calculate TCP/UDP checksum.
struct IPv4PseudoHeader {
  UINT32 source_address;
  UINT32 dest_address;
  UINT8 reserved;
  UINT8 protocol;
  UINT16 length;
};

// IPv6 header: https://tools.ietf.org/html/rfc2460#section-3
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |Version| Traffic Class |           Flow Label                  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         Payload Length        |  Next Header  |   Hop Limit   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                                                               +
// |                                                               |
// +                         Source Address                        +
// |                                                               |
// +                                                               +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                                                               +
// |                                                               |
// +                      Destination Address                      +
// |                                                               |
// +                                                               +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
struct IPv6Header {
  UINT32 flow_label : 20;
  UINT32 traffic_class : 8;
  UINT32 version : 4;
  UINT16 payload_length;
  UINT8 next_header;
  UINT8 hop_limit;
  UINT32 source_address[4];
  UINT32 dest_address[4];
};
static_assert(sizeof(IPv6Header) == 40, "Size of IPv6Header != 40");

// TCP header: https://tools.ietf.org/html/rfc793#section-3.1
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          Source Port          |       Destination Port        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Sequence Number                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Acknowledgment Number                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Data |           |U|A|P|R|S|F|                               |
// | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
// |       |           |G|K|H|T|N|N|                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |           Checksum            |         Urgent Pointer        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Options                    |    Padding    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                             data                              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
struct TcpHeader {
  UINT16 source_port;
  UINT16 dest_port;
  UINT32 seq_number;
  UINT32 ack_number;
  UINT8 reserved : 4;  // Ignore the NS experimental flag.
  UINT8 data_offset : 4;
  UINT8 flags;
  UINT16 window;
  UINT16 checksum;
  UINT16 urgent_pointer;
};
static_assert(sizeof(TcpHeader) == 20, "Size of TcpHeader != 20");
constexpr UINT kTcpFlagPSH = 0x8;
constexpr UINT kTcpFlagACK = 0x10;

// UDP header: https://tools.ietf.org/html/rfc768
//  0      7 8     15 16    23 24    31
// +--------+--------+--------+--------+
// |     Source      |   Destination   |
// |      Port       |      Port       |
// +--------+--------+--------+--------+
// |                 |                 |
// |     Length      |    Checksum     |
// +--------+--------+--------+--------+
struct UdpHeader {
  UINT16 source_port;
  UINT16 dest_port;
  UINT16 length;
  UINT16 checksum;
};
static_assert(sizeof(UdpHeader) == 8, "Size of UdpHeader != 8");
#include <poppack.h>

constexpr size_t kEthHeaderSize = sizeof(ETH_HEADER);
constexpr size_t kIPv4HeaderSize = sizeof(IPv4Header);
constexpr size_t kIPv6HeaderSize = sizeof(IPv6Header);

// Max option size is 40
constexpr size_t kMaxTcpHeaderSize = sizeof(TcpHeader) + 40;
// IPv4 + ip options.
constexpr size_t kMaxIPHeaderSize = 60;
// IEEE 802.1ad allow 2 VLAN tag and each is 4 bytes.
constexpr size_t kMaxEthHeaderSize = kEthHeaderSize + 8;
// Maximum size of a TCP or UDP packet.
constexpr size_t kMaxPacketSize = MAXUINT16;

void LogMacAddress(const char* message, const UCHAR* mac);

void LogRxChecksum(const NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO& csum_info,
                   UINT16 packet_flag);
#endif  // NET_UTILS_H_
