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

#include "netutils.h"  // NOLINT: include directory

#include "trace.h"  // NOLINT: include directory

#include "netutils.tmh"  // NOLINT: include directory

void LogMacAddress(const char* message, const UCHAR* mac) {
  DEBUGP(GVNIC_INFO, "%s : %x-%x-%x-%x-%x-%x", message, mac[0], mac[1], mac[2],
         mac[3], mac[4], mac[5]);
}

void LogRxChecksum(const NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO& csum_info,
                   UINT16 packet_flag) {
  DEBUGP(GVNIC_VERBOSE,
         "[%s] Rx Csum result: flag - %#x ip-%d:%d tcp-%d:%d udp-%d:%d",
         __FUNCTION__, packet_flag, csum_info.Receive.IpChecksumSucceeded,
         csum_info.Receive.IpChecksumFailed,
         csum_info.Receive.TcpChecksumSucceeded,
         csum_info.Receive.TcpChecksumFailed,
         csum_info.Receive.UdpChecksumSucceeded,
         csum_info.Receive.UdpChecksumFailed);
}
