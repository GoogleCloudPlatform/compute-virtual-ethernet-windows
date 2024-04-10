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

// This file contains all the structures defined and accepted by the device. It
// needs to stay in sync with all future device spec(gvnic_abi.h) changes.
#ifndef ABI_H_
#define ABI_H_

#include <ndis.h>

#include "netutils.h"  // NOLINT: include directory

constexpr int kCacheLineSize = 64;

#include <pshpack1.h>  // NOLINT: Turns packing of structures on.

// Gvnic BAR0 Config and Status Registers.
struct GvnicDeviceConfig {
  UINT32 dev_status;
  UINT32 dri_status;
  UINT32 max_tx_queues;
  UINT32 max_rx_queues;
  UINT32 admin_queue_pfn;
  UINT32 admin_queue_doorbell;
  UINT32 admin_queue_event_counter;
  UINT8 reserved[2];
  UINT8 dma_mask;
  UINT8 driver_version;
};
static_assert(sizeof(GvnicDeviceConfig) == 0x20,
              "Size of GvnicDeviceConfig != 0x20");

// If the device needs the driver to ignore the flow table and route all
// traffic into Traffic Class 0, it will set this bit. The device will clear
// this bit when it no longer needs it.
constexpr UINT32 kDeviceStatusIgnoreFlowTable = 0x1;
// If the device needs a reset it will set this bit to request the driver reset
// it. The device will clear this bit if it no longer needs a reset or when a
// successful reset happens.
constexpr UINT32 kDeviceStatusReset = 0x1 << 1;

// Admin queue opcodes
enum AdminQueueCommandOpcode {
  kDescribeDevice = 0x1,
  kConfigureDeviceResources = 0x2,
  kRegisterPageList = 0x3,
  kUnregisterPageList = 0x4,
  kCreateTxQueue = 0x5,
  kCreateRxQueue = 0x6,
  kDestroyTxQueue = 0x7,
  kDestroyRxQueue = 0x8,
  kDeconfigureDeviceResources = 0x9,
  kSetWindowsRssParameters = 0xa,
};

// Admin queue status code
enum AdminQueueCommandStatus : UINT32 {
  kAdminQueueCommandUnset = 0,
  kAdminQueueCommandPassed = 1,
  kAdminQueueCommandAbortedError = 0xFFFFFFF0,
  kAdminQueueCommandAlreadyExistsError = 0xFFFFFFF1,
  kAdminQueueCommandCancelledError = 0xFFFFFFF2,
  kAdminQueueCommandDataLossError = 0xFFFFFFF3,
  kAdminQueueCommandDeadlineExceededError = 0xFFFFFFF4,
  kAdminQueueCommandFailedPreconditionError = 0xFFFFFFF5,
  kAdminQueueCommandInternalError = 0xFFFFFFF6,
  kAdminQueueCommandInvalidArgumentError = 0xFFFFFFF7,
  kAdminQueueCommandNotFoundError = 0xFFFFFFF8,
  kAdminQueueCommandOutOfRangeError = 0xFFFFFFF9,
  kAdminQueueCommandPermissionDeniedError = 0xFFFFFFFA,
  kAdminQueueCommandUnauthenticatedError = 0xFFFFFFFB,
  kAdminQueueCommandResourceExhaustedError = 0xFFFFFFFC,
  kAdminQueueCommandUnavailableError = 0xFFFFFFFD,
  kAdminQueueCommandUnimplementedError = 0xFFFFFFFE,
  kAdminQueueCommandUnknownError = 0xFFFFFFFF,
};

struct DescribeDeviceCommand {
  UINT64 device_descriptor_address;
  UINT32 device_descriptor_version;
  UINT32 available_length;
};

#define VERSION_STR_LEN 128

enum DriverOSType : UINT8 {
  //  kDriverOSLinux = 1,
  kDriverOSWindows = 2,
  //  kDriverOSFreeBSD = 3,
  //  kDriverOSESXi = 4,
  //  kDriverOSDPDK = 5,
};

struct DeviceInfo {
  UINT8 os_type;
  UINT8 driver_major;
  UINT8 driver_minor;
  UINT8 driver_sub;
  UINT32 os_version_major;
  UINT32 os_version_minor;
  UINT32 os_version_sub;
  UINT64 driver_capability_flags[4];
  UINT8 os_version_str1[VERSION_STR_LEN];
  UINT8 os_version_str2[VERSION_STR_LEN];
};

struct ConfigureDeviceResourcesCommand {
  UINT64 counter_array;
  UINT64 irq_db_addr_base;
  UINT32 num_counters;
  UINT32 num_irq_dbs;
  UINT32 irq_db_stride;
  UINT32 ntfy_blk_msix_base_idx;
};

// page_list_address is list of physical pages allocated by Driver Device will
// copy all page physical address into its own memory and driver releases it
// after this call.
struct RegisterPageListCommand {
  UINT32 page_list_id;
  UINT32 num_pages;
  UINT64 page_list_address;
};

struct UnregisterPageListCommand {
  UINT32 page_list_id;
};

// Special QueuePageList Id if using raw addressing.
constexpr UINT32 kRawAddressingPageListId = 0xFFFFFFFF;

// Windows can fragment the header across multiple entries in the scatter
// gather list, and the on-host virtual switch requires that the header be
// stored contiguously within the first packet descriptor. If the overall packet
// is longer than 182 bytes and the first scatter gather element is smaller than
// 182 bytes, we copy 182 bytes into a temporary buffer to form the first packet
// descriptor.
// LINT.IfChange(BytesRequiredInTxPacketDescriptor)
constexpr UINT32 kBytesRequiredInTxPacketDescriptor = 182;
// LINT.ThenChange()

// The on-host virtual switch limits the number of descriptors a single packet
// can use. Unless buffered, in raw addressing mode each scatter gather entry
// will require a descriptor.
// LINT.IfChange(MaxDescriptorsPerPacket)
constexpr UINT32 kMaxDescriptorsPerPacket = 18;
// LINT.ThenChange()

// This is used when configuring the MSI-X entries, which happens before we can
// query the device for the actual number of tx and rx slices (each of which
// requires a dedicated entry). One MSI-X entry is expected per CPU up to this
// amount for both rx and tx, with a single MSI-X entry reserved for the
// management interrupt.
// LINT.IfChange(kMaxPerDirectionTrafficSlices)
constexpr UINT32 kMaxPerDirectionTrafficSlices = 16;
// LINT.ThenChange()

// Both queue_resources_addr and tx_ring_addr are allocated by driver and needs
// to be released by driver after calling DestoryTransmitQueue.
struct CreateTransmitQueueCommand {
  UINT32 queue_id;
  UINT32 priority;
  UINT64 queue_resources_addr;
  UINT64 tx_ring_addr;
  UINT32 queue_page_list_id;
  UINT32 notify_blk_id;

  UINT8 reserved[12];
};

// queue_resources_addr, rx_desc_ring_addr and rx_data_ring_addr are allocated
// by driver and needs to be released by driver after calling
// DestroyReceiveQueue.
struct CreateReceiveQueueCommand {
  UINT32 queue_id;
  UINT32 slice;
  UINT32 group;
  UINT32 notify_blk_id;
  UINT64 queue_resources_addr;
  UINT64 rx_desc_ring_addr;
  UINT64 rx_data_ring_addr;
  UINT32 queue_page_list_id;

  UINT8 reserved[4];
};

struct DestroyTransmitQueueCommand {
  UINT32 queue_id;
};

struct DestroyReceiveQueueCommand {
  UINT32 queue_id;
};

struct SetWindowsRssParametersCommand {
  UINT16 supported_hash_type;
  UINT8 hash_function;
  UINT8 reserved;
  UINT16 hash_secret_key_size;
  UINT16 queue_indirection_table_size;
  UINT64 hash_secret_key_addr;
  UINT64 queue_indirection_table_addr;
};

struct AdminQueueCommand {
  UINT32 opcode;
  UINT32 status;
  union {
    DescribeDeviceCommand describe_device;
    ConfigureDeviceResourcesCommand configure_device_resources;
    RegisterPageListCommand register_page_list;
    UnregisterPageListCommand unregister_page_list;
    CreateTransmitQueueCommand create_transmit_queue;
    CreateReceiveQueueCommand create_receive_queue;
    DestroyTransmitQueueCommand destroy_transmit_queue;
    DestroyReceiveQueueCommand destroy_receive_queue;
    SetWindowsRssParametersCommand set_rss_parameters;
    char padding[56];
  };
};

constexpr size_t kAdminQeueueCommandSize = sizeof(AdminQueueCommand);

struct DeviceOption {
  UINT16 option_id;
  UINT16 option_length;
  UINT32 required_features_mask;
};

struct DeviceDescriptor {
  UINT64 max_registered_pages;
  UINT16 num_rx_groups;
  UINT16 tx_queue_size;
  UINT16 rx_queue_size;
  UINT16 default_num_slices;
  UINT16 mtu;
  UINT16 event_counters;
  UINT16 tx_pages_per_qpl;
  UINT16 reserved1;
  UINT8 mac[kEthAddrLen];
  UINT16 num_device_options;
  UINT16 total_length;

  UINT8 reserved2[6];

  // Support up-to 20 device option.
  DeviceOption device_option[20];
};

// DeviceOption IDs
constexpr UINT16 kSupportsRawAddressing = 1;

// Event counter registered with the device. It must be in sizeof(UINT32).
// For now, it is used in tx_ring to record how many packets is sent.
union DeviceCounter {
  UINT32 packets_sent;
};

// Interrupt Request flag.
constexpr UINT32 kInterruptRequestACK = 1u << 31;
constexpr UINT32 kInterruptRequestMask = 1u << 30;
constexpr UINT32 kInterruptRequestEvent = 1u << 29;

// Device will set these fields and let driver knows how to send notice to it.
struct QueueResources {
  union {
    struct {
      volatile UINT32 doorbell_index;
      volatile UINT32 counter_index;
    };
    UINT8 reserved[64];
  };
};

// The following illustration shows a general TX descriptor format. The fields
// that are filled in are common to most TX descriptor types. The blank fields
// vary depending on the descriptor type, and they are documented separately for
// each descriptor.
//
// |<---- byte 0 ---->|<---- byte 1 --->|<---- byte 2 ---->|<---- byte 3 ---->|
//  31              24 23             16 15               8 7                0
//
// ----------------------------------------------------------------------------
// |    type_flags    | checksum_offset |    l4_offset     | descriptor_count |
// ----------------------------------------------------------------------------
// |         packet_length              |           segment_length            |
// ----------------------------------------------------------------------------
// |             segment_addr_high (high bits of segment address)             |
// ----------------------------------------------------------------------------
// |             segment_addr_low (lower bits of segment address)             |
// ----------------------------------------------------------------------------
//
// Byte 0: 'type_flags' where upper 4-bits store the type of TX descriptor and
// lower 4-bits are used for descriptor-specific flags.
// Byte 1: Offset to L4 checksum (2-byte units).
// Byte 2: Offset to IP payload (2-byte units).
// Byte 3: Total num of descriptors of a send req.
// Bytes 4-5: Sum (in bytes) of all segments.
// Bytes 6-7: 'segment_length' that has the size (in bytes) of the segment
// described in the descriptor.
//
// Bytes 8-15: 'segment_address' is the 64-bit address of the data
// segment for this send request.  Additional segments have their own
// segment descriptors. These addresses are used for DMA transfers
// from host memory to NIC. If the queue is opened in a 'TRUSTED'
// mode, this address is an host address. If the queue is opened in a
// non-trusted mode, this address serves as an offset w.r.t the TX
// data buffer memory region; in this case, the lower 24 bits (of
// segment_address) are used as the offset in the TX data buffer.

// Mandatory descriptor for a standard or a TSO send request. If this is
// standard packet descriptor, it can be followed by zero or more segment
// descriptors (GQTxSegmentDescriptor). If this is a TSO packet descriptor, it
// must be followed by a segment descriptor with TSO-specific fields, and any
// additional segment descriptors for other additional segments.
struct TxPacketDescriptor {
  UINT8 type_flags;
  UINT8 checksum_offset;   // Byte 1: Offset to L4 checksum (2-byte units).
  UINT8 l4_offset;         // Byte 2: Offset to IP payload (2-byte units).
  UINT8 descriptor_count;  // Byte 3: Total num of descriptors of a send req.
  UINT16 packet_length;    // Bytes 4-5: Sum (in bytes) of all segments.
  UINT16 segment_length;
  UINT64 segment_address;
};

// Optional descriptor for each additional data segment. The first data segment
// is included in the GQTxPacketDesriptor or GQTxFwPacketDescriptor, and each of
// the remaining data segments have a separate GQTxSegmentDescriptor.
struct TxSegmentDescriptor {
  UINT8 type_flags;
  UINT8 l3_offset;
  UINT16 reserved;  // Bytes 2-3: unused.
  UINT16 tso_mss;   // Bytes 4-5: TSO MSS (size of TSO-generated segments).
  UINT16 segment_length;
  UINT64 segment_address;
};

// Transmit descriptor Types
enum TxDescriptorType {
  kTxDescriptorTypeSTD = (0x0 << 4),  // Standard Package descriptor
  kTxDescriptorTypeTSO = (0x1 << 4),  // TSO package descriptor
  kTxDescriptorTypeSEG = (0x2 << 4)   // Segment descriptor
};

constexpr UINT8 kTxFlagChecksumOffload = (1 << 0);   // Need checksum offload.
constexpr UINT8 kTxTsoIpV6 = (1 << 1);               // IPV6 TSO.
constexpr UINT8 kTxFlagTimestamp = (1 << 2);         // Timestamp required.
constexpr UINT8 kTxFlagCryptoDescriptor = (1 << 3);  // Encryption is included.

union TxDescriptor {
  TxPacketDescriptor package_descriptor;
  TxSegmentDescriptor segment_descriptor;
};

// This illustration shows the 64-byte RX descriptor visible to the user.
//
// |<---- byte 0 ---->|<---- byte 1 --->|<---- byte 2 ---->|<---- byte 3 ---->|
//  31              24 23             16 15               8 7                0
// |                     48 bytes of padding                                  |
// ----------------------------------------------------------------------------
// |                             rss hash                                     |
// ----------------------------------------------------------------------------
// |                 mss                |             reserved                |
// ----------------------------------------------------------------------------
// |   header_length  |  header_offset  |           checkum (optional)        |
// ----------------------------------------------------------------------------
// |            packet_length           |         flags              |sequence|
// |                                    |       (13 bits)            |(3 bits)|
// ----------------------------------------------------------------------------
//
struct RxDescriptor {
  UINT8 padding[48];
  UINT32 rss_hash;
  // This field serves two purposes:
  // - GRO MSS used for visualization.
  // - For packet-error-handling specification.
  UINT16 mss_or_error_type;
  UINT16 reserved;
  // Incoming packet's header length (in 2-byte units) as specified by HW/FW
  // (includes the 2-byte header padding if packet is not processed by FW).
  UINT8 header_length;
  // Number of alignment units from the start of RX_DESC_Q entry to where the
  // packet data starts.
  UINT8 header_offset;
  // Partial checksum computed by the hardware.
  UINT16 checksum;
  // Length, in bytes, of packet as written into the host memory (includes the
  // 2-byte header padding).
  UINT16 packet_length;
  // Status flags for RX packet and sequence number
  UINT16 flags_sequence;
};

// The length of sequence bit in flags_sequence field of RxDescriptor.
// gvnic is a big endian device and need to do field shift instead of struct
// bit field to get the correct value.
constexpr UINT kRxSequenceLength = 3;

// RxDescriptor flags fields.
enum RxDescriptorFlag {
  kRxDescriptorFlagIPv4 = (1 << 4),
  kRxDescriptorFlagIPv6 = (1 << 5),
  kRxDescriptorFlagTcp = (1 << 6),
  kRxDescriptorFlagUdp = (1 << 7)
};

struct RxDataRingSlot {
  UINT64 queue_page_list_offset;
};

#include <poppack.h>  // NOLINT: Turns packing of structures off.

// Use forward declaration to avoid circular dependency.
class TxRing;
class RxRing;

// NotifyBlock is required to be cache line aligned.
// Device only requires that first 4 bytes is irq_db_index and ignore all other
// fields, so we don't need this struct to be packed.
__declspec(align(kCacheLineSize)) struct NotifyBlock {
  volatile UINT32 irq_db_index;  // Set by device - must be first field.
  TxRing* tx_ring;
  RxRing** rx_rings;
  UINT32 num_rx_rings;
  KAFFINITY processor_affinity;
};

#endif  // ABI_H_
