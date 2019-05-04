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

#ifndef TX_NET_BUFFER_LIST_
#define TX_NET_BUFFER_LIST_

#include <ndis.h>

// Wrapper of NET_BUFFER_LIST to allow list operation and store actually memory
// usage.
struct TxNetBufferList {
  LIST_ENTRY list_entry;
  NET_BUFFER_LIST* net_buffer_list;
  NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO checksum_info;
  NDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO lso_info;
};

#endif  // TX_NET_BUFFER_LIST_
