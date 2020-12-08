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

#ifndef RX_RING_ENTRY_H_
#define RX_RING_ENTRY_H_

#include <ndis.h>
#include "abi.h"       // NOLINT: include directory
#include "netutils.h"  // NOLINT: include directory

// Struct to group related rx ring fields into one block.
//
// Each RxRingEntry will hold one rx packet and it can exist either on first
// half or second half of the page. As a result, the structure holds a pair of
// pre-calculated mdl, packet_addr, eth_header, ip_header for fast rx procssing.
__declspec(align(kCacheLineSize)) struct RxRingEntry {
  // Pointer to RxDescirptor.
  RxDescriptor* descriptor;
  // Pointer to the RxDataRingSlot shared between device and driver.
  // Driver use queue_page_list_offset inside the data structure to indicate
  // next write location.
  RxDataRingSlot* data;
  // Count for number of pending packets inside this slot.
  INT16 pending_count;
  // Count for number of pending packets inside this ring.
  INT16* ring_pending_count;
  // Raw address of for the packet.
  void* packet_addr[2];
  // Eth header address.
  ETH_HEADER* eth_header[2];
  // Ip header address.
  IPv4Header* ipv4_header[2];
  // Store pre-allocated net_buffer_list.
  NET_BUFFER_LIST* net_buffer_lists[2];

  // Used for tracking merged packets for RSC.
  RxRingEntry* rsc_next;
  RxRingEntry* rsc_last;
};

#endif  // RX_RING_ENTRY_H_
