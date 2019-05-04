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

#include "tx_ring.h"  // NOLINT: include directory

#include <ndis.h>

#include "abi.h"                 // NOLINT: include directory
#include "adapter_resource.h"    // NOLINT: include directory
#include "adapter_statistics.h"  // NOLINT: include directory
#include "admin_queue.h"         // NOLINT: include directory
#include "device_fifo_queue.h"   // NOLINT: include directory
#include "netutils.h"            // NOLINT: include directory
#include "ring_base.h"           // NOLINT: include directory
#include "spin_lock_context.h"   // NOLINT: include directory
#include "trace.h"               // NOLINT: include directory
#include "tx_net_buffer.h"       // NOLINT: include directory
#include "tx_net_buffer_list.h"  // NOLINT: include directory
#include "utils.h"               // NOLINT: include directory

#include "tx_ring.tmh"  // NOLINT: trace message header

namespace {
// One notify block per slice.
inline UINT GetTxNotifyBlockId(UINT slice) { return slice; }

TxNetBufferList* GetTxNetBufferListFromListEntry(const LIST_ENTRY& entry) {
  return reinterpret_cast<TxNetBufferList*>(
      CONTAINING_RECORD(&entry, TxNetBufferList, list_entry));
}

// Build descriptor for TxPacket.
void FillTxPacketDescriptor(const TxNetBuffer& tx_net_buffer,
                            const PacketSegmentInfo& segment_info,
                            TxPacketDescriptor* descriptor) {
  if (tx_net_buffer.is_lso()) {
    descriptor->type_flags = kTxDescriptorTypeTSO | kTxFlagChecksumOffload;
    // Gvnic requires both checksum offset and l4 offset in 2-byte unit.
    descriptor->checksum_offset =
        tx_net_buffer.GetChecksumOffsetWithinL4() >> 1;
    descriptor->l4_offset = tx_net_buffer.GetL4Offset() >> 1;
  } else if (tx_net_buffer.is_checksum_offload()) {
    descriptor->type_flags = kTxDescriptorTypeSTD | kTxFlagChecksumOffload;
    // Gvnic requires both checksum offset and l4 offset in 2-byte unit.
    descriptor->checksum_offset =
        tx_net_buffer.GetChecksumOffsetWithinL4() >> 1;
    descriptor->l4_offset = tx_net_buffer.GetL4Offset() >> 1;
  } else {
    descriptor->type_flags = kTxDescriptorTypeSTD;
    descriptor->checksum_offset = 0;
    descriptor->l4_offset = 0;
  }

  descriptor->descriptor_count = 1 + segment_info.data_segment_count;
  descriptor->packet_length =
      RtlUshortByteSwap((USHORT)tx_net_buffer.data_length());
  descriptor->segment_length =
      RtlUshortByteSwap((USHORT)segment_info.packet_length);
  descriptor->segment_address =
      RtlUlonglongByteSwap(segment_info.packet_offset);
}

// Build descriptor for TxSegment.
void FillTxSegmentDescriptor(UINT32 offset, UINT32 length,
                             const TxNetBuffer& tx_net_buffer,
                             TxSegmentDescriptor* descriptor) {
  descriptor->type_flags = kTxDescriptorTypeSEG;
  descriptor->segment_length = RtlUshortByteSwap((USHORT)length);
  descriptor->segment_address = RtlUlonglongByteSwap(offset);

  if (tx_net_buffer.is_lso()) {
    if (tx_net_buffer.is_lso_ipv6()) {
      descriptor->type_flags |= kTxTsoIpV6;
    }
    descriptor->tso_mss = RtlUshortByteSwap(tx_net_buffer.max_segment_size());
    // L3 offset is in 2 byte unit.
    descriptor->l3_offset = tx_net_buffer.GetL3Offset() >> 1;
  }
}

}  // namespace

TxRing::~TxRing() {
  PAGED_CODE();
  Release();
}

bool TxRing::Init(UINT32 id, UINT32 slice, UINT32 traffic_class,
                  UINT32 num_descriptor, QueuePageList* queue_page_list,
                  UINT32 notify_id, AdapterResources* adapter_resource,
                  AdapterStatistics* statistics,
                  const DeviceCounter* device_counters) {
  PAGED_CODE();
  // num_descriptor is expected to be power of 2.
  NT_ASSERT((num_descriptor & (num_descriptor - 1)) == 0);

  current_net_buffer_to_send_ = nullptr;
  current_net_buffer_list_to_send_ = nullptr;

  num_request_segments_ = 0;
  num_sent_segments_ = 0;
  num_descriptor_ = num_descriptor;
  descriptor_mask_ = num_descriptor_ - 1;
  NdisInitializeListHead(&packet_to_send_);
  NdisAllocateSpinLock(&packet_list_spin_lock_);
  eth_header_len_.IPv4 = eth_header_len_.IPv6 = kEthAddrLen;

  DEBUGP(GVNIC_INFO, "[%s] Allocating resource for tx: %u with %u descriptors",
         __FUNCTION__, id, num_descriptor_);

  if (!RingBase::Init(id, slice, traffic_class, queue_page_list, notify_id,
                      adapter_resource, statistics, device_counters)) {
    return false;
  }

  if (!descriptor_ring_.Allocate(miniport_handle(), num_descriptor_)) {
    DEBUGP(GVNIC_ERROR,
           "[%s] ERROR: Memory allocation failed for tx descriptor ring",
           __FUNCTION__);
    return false;
  }

  segment_allocated_size_ =
      AllocateMemory<UINT32>(miniport_handle(), num_descriptor_);

  if (!segment_allocated_size_) {
    DEBUGP(GVNIC_ERROR,
           "[%s] ERROR: Memory allocation failed for segment allocated size "
           "array.",
           __FUNCTION__);
    return false;
  }

  device_queue_.Init(queue_page_list->pages(), queue_page_list->num_pages());

  return true;
}

void TxRing::Release() {
  PAGED_CODE();

  CleanPendingPackets();
  descriptor_ring_.Release();
  FreeMemory(segment_allocated_size_);
  RingBase::Release();
  NdisFreeSpinLock(&packet_list_spin_lock_);
}

void TxRing::SendBufferList(PNET_BUFFER_LIST net_buffer_list,
                            bool is_dpc_level) {
  TxNetBufferList* net_packet =
      AllocateMemory<TxNetBufferList>(miniport_handle());

  if (!net_packet) {
    CompleteNetBufferListWithStatus(net_buffer_list, NDIS_STATUS_RESOURCES,
                                    is_dpc_level);
    return;
  }

  net_packet->net_buffer_list = net_buffer_list;

  // Extract Checksum, lso info as it is common for all net_buffers inside.
  net_packet->checksum_info.Value =
      NET_BUFFER_LIST_INFO(net_buffer_list, TcpIpChecksumNetBufferListInfo);
  net_packet->lso_info.Value =
      NET_BUFFER_LIST_INFO(net_buffer_list, TcpLargeSendNetBufferListInfo);

  SpinLockContext lock_context(&packet_list_spin_lock_, is_dpc_level);
  InsertTailList(&packet_to_send_, &net_packet->list_entry);
  SendNetPackets();
}

void TxRing::ProcessCompletePackets() {
  NT_ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);
  UINT32 packets_sent = ReadPacketsSent();
  UINT32 buffer_to_free = 0;

  while (packets_sent > num_sent_segments_) {
    UINT32 segment_idx = num_sent_segments_ & descriptor_mask_;
    buffer_to_free += segment_allocated_size_[segment_idx];
    num_sent_segments_++;
  }

  if (buffer_to_free > 0) {
    SpinLockContext lock_context(&packet_list_spin_lock_, true);
    device_queue_.FreeAllocatedBuffer(buffer_to_free, packet_list_spin_lock_);
  }

  DEBUGP(GVNIC_VERBOSE, "[%s] TxRing id - %u: requested - %u, done - %u",
         __FUNCTION__, id(), num_request_segments_, num_sent_segments_);
}

// Offload capacity is not enabled. The only packet we will get for now is
// normal packet.
_Requires_lock_held_(packet_list_spin_lock_) void TxRing::SendNetPackets() {
  if (current_net_buffer_to_send_ == nullptr) {
    current_net_buffer_to_send_ = GetNextNetBufferToSend();
  }

  UINT current_num_request = num_request_segments_;

  // Send as many packets as we can until there is nothing to send or
  // driver run out of resources(descriptor or queue page list).
  while (current_net_buffer_to_send_ != nullptr) {
    // We don't know the exact descriptor requirement yet but check for the
    // worst case (header + 2 data segment). We have a large number of
    // descriptors so this usually won't be an issue.
    if (GetAvailableDescriptors() < 3) {
      break;
    }

    // Create Wrapper for the NET_BUFFER and load the address.
    TxNetBuffer tx_net_buffer(current_net_buffer_to_send_,
                              current_net_buffer_list_to_send_->checksum_info,
                              current_net_buffer_list_to_send_->lso_info,
                              eth_header_len_);
    if (tx_net_buffer.eth_header() == nullptr) {
      DEBUGP(GVNIC_ERROR, "ERROR: [%s] Map NET_BUFFER failed.", __FUNCTION__);
      break;
    }

    // Get index of the rx descriptor.
    int desc_idx = num_request_segments_ & descriptor_mask_;

    // Copy the package into device queue.
    PacketSegmentInfo packet_segment_info = device_queue_.CopyNetBuffer(
        current_net_buffer_to_send_, tx_net_buffer.is_lso(),
        packet_list_spin_lock_);
    if (packet_segment_info.allocated_length == 0) {
      // copy failed due to system resources are low or exhausted.
      // Will retry on next SendNetPackets.
      break;
    }

    // Fill out the package descriptor.
    TxDescriptor* desc = &descriptor_ring_.virtual_address()[desc_idx];
    FillTxPacketDescriptor(tx_net_buffer, packet_segment_info,
                           &desc->package_descriptor);
    segment_allocated_size_[desc_idx] = packet_segment_info.allocated_length;

    // Fill out the data segment descriptors if any.
    for (UINT32 i = 0; i < packet_segment_info.data_segment_count; i++) {
      UINT32 seg_desc_idx = (desc_idx + 1 + i) & descriptor_mask_;
      TxDescriptor* seg_desc =
          &descriptor_ring_.virtual_address()[seg_desc_idx];
      FillTxSegmentDescriptor(packet_segment_info.data_segment_info[i].offset,
                              packet_segment_info.data_segment_info[i].length,
                              tx_net_buffer, &seg_desc->segment_descriptor);
      segment_allocated_size_[seg_desc_idx] =
          packet_segment_info.data_segment_info[i].allocated_length;
    }

    UINT32 total_segment_count = 1 + packet_segment_info.data_segment_count;
    num_request_segments_ += total_segment_count;

    // Update statistics.
    statistics()->AddSentPacket(tx_net_buffer.data_length(),
                                tx_net_buffer.eth_header());

    // Move to next net_buffer.
    current_net_buffer_to_send_ = GetNextNetBufferToSend();
  }

  if (current_num_request != num_request_segments_) {
    WriteDoorbell(num_request_segments_);
  }

  DEBUGP(GVNIC_VERBOSE, "[%s] TxRing id - %u: requested - %u, done - %u",
         __FUNCTION__, id(), num_request_segments_, num_sent_segments_);
}

void TxRing::CompleteNetBufferListWithStatus(NET_BUFFER_LIST* net_buffer_list,
                                             NDIS_STATUS status,
                                             bool is_dpc_level) {
  NET_BUFFER_LIST_STATUS(net_buffer_list) = status;
  NdisMSendNetBufferListsComplete(
      miniport_handle(), net_buffer_list,
      is_dpc_level ? NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL : 0);
}

void TxRing::CleanPendingPackets() {
  SpinLockContext lock_context(&packet_list_spin_lock_, false);

  if (IsListInitialized(packet_to_send_)) {
    while (!IsListEmpty(&packet_to_send_)) {
      TxNetBufferList* tx_net_buffer_list =
          reinterpret_cast<TxNetBufferList*>(CONTAINING_RECORD(
              RemoveHeadList(&packet_to_send_), TxNetBufferList, list_entry));
      CompleteNetBufferListWithStatus(tx_net_buffer_list->net_buffer_list,
                                      NDIS_STATUS_FAILURE,
                                      /*is_dpc_level=*/false);
      FreeMemory(tx_net_buffer_list);
    }
  }
}

NET_BUFFER* TxRing::GetNextNetBufferToSend() {
  // Check whether we have next net_buffer.
  if (current_net_buffer_to_send_ != nullptr) {
    NET_BUFFER* next_net_buffer =
        NET_BUFFER_NEXT_NB(current_net_buffer_to_send_);
    if (next_net_buffer != nullptr) {
      return next_net_buffer;
    } else {
      // The current net_buffer_list is completed. Move it to to_complete list.
      CompleteNetBufferListWithStatus(
          current_net_buffer_list_to_send_->net_buffer_list,
          NDIS_STATUS_SUCCESS, true);
      FreeMemory(current_net_buffer_list_to_send_);
      current_net_buffer_list_to_send_ = nullptr;
    }
  }

  // Need to get the net_buffer from the head of packet_to_send_.
  if (IsListEmpty(&packet_to_send_)) {
    // Have nothing to send.
    return nullptr;
  } else {
    current_net_buffer_list_to_send_ =
        GetTxNetBufferListFromListEntry(*RemoveHeadList(&packet_to_send_));
    NET_BUFFER* net_buffer = NET_BUFFER_LIST_FIRST_NB(
        current_net_buffer_list_to_send_->net_buffer_list);
    NT_ASSERT(net_buffer != nullptr);

    return net_buffer;
  }
}
