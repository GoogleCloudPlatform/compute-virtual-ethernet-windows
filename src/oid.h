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

#ifndef OID_H_
#define OID_H_

#include <ndis.h>

// List of mandatory Oids.
// statistics OIDs:
// https://docs.microsoft.com/en-us/windows-hardware/drivers/network/ndis-general-statistics-oids
// interface OIDs:
// https://docs.microsoft.com/en-us/windows-hardware/drivers/network/ndis-network-interface-oids
// Ethernet Statistics OIDs:
// https://docs.microsoft.com/en-us/windows-hardware/drivers/network/ethernet-statistics-oids
constexpr NDIS_OID kSupportedOids[] = {
    OID_GEN_STATISTICS,             // Query
    OID_GEN_XMIT_OK,                // Query
    OID_GEN_RCV_OK,                 // Query
    OID_GEN_TRANSMIT_BUFFER_SPACE,  // Query
    OID_GEN_RECEIVE_BUFFER_SPACE,   // Query
    OID_GEN_TRANSMIT_BLOCK_SIZE,    // Query
    OID_GEN_RECEIVE_BLOCK_SIZE,     // Query
    OID_GEN_VENDOR_ID,              // Query
    OID_GEN_VENDOR_DESCRIPTION,     // Query
    OID_GEN_VENDOR_DRIVER_VERSION,  // Query
    OID_GEN_CURRENT_PACKET_FILTER,  // Set
    OID_GEN_CURRENT_LOOKAHEAD,      // Query and Set
    OID_GEN_MAXIMUM_TOTAL_SIZE,     // Query
    OID_GEN_LINK_PARAMETERS,        // Set
    OID_GEN_INTERRUPT_MODERATION,   // Query and Set
    OID_IP4_OFFLOAD_STATS,          // Deprecated
    OID_TCP_OFFLOAD_PARAMETERS,     // Set
    OID_OFFLOAD_ENCAPSULATION,      // Set, Query is handled by NDIS

    OID_802_3_PERMANENT_ADDRESS,  // Query
    OID_802_3_CURRENT_ADDRESS,    // Query

    OID_PNP_SET_POWER,    // Set
    OID_PNP_QUERY_POWER,  // Query

    OID_GEN_RECEIVE_SCALE_PARAMETERS,  // Set, Query is handled by NDIS
};

extern "C" {
MINIPORT_OID_REQUEST GvnicOidRequest;
MINIPORT_CANCEL_OID_REQUEST GvnicOidCancelRequest;
#if NDIS_SUPPORT_NDIS61
MINIPORT_DIRECT_OID_REQUEST GvnicDirectOidRequest;
MINIPORT_CANCEL_DIRECT_OID_REQUEST GvnicCancelDirectOidRequest;
#endif  // NDIS_SUPPORT_NDIS61
}
#endif  // OID_H_
