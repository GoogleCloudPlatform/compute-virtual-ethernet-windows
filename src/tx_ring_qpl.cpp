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

#include "tx_ring_qpl.h"  // NOLINT: include directory

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

#include "tx_ring_qpl.tmh"       // NOLINT: trace message header

namespace {

TxNetBufferList* GetTxNetBufferListFromListEntry(const LIST_ENTRY& entry) {
  return reinterpret_cast<TxNetBufferList*>(
      CONTAINING_RECORD(&entry, TxNetBufferList, list_entry));
}

}  // namespace

bool TxRingQpl::Init(UINT32 id, UINT32 slice, UINT32 traffic_class,
                     UINT32 num_descriptor, QueuePageList* queue_page_list,
                     UINT32 notify_id, AdapterResources* adapter_resource,
                     AdapterStatistics* statistics,
                     const DeviceCounter* device_counters) {
  PAGED_CODE();

  NdisInitializeListHead(&packet_to_send_);

  current_net_buffer_to_send_ = nullptr;
  current_net_buffer_list_to_send_ = nullptr;

  DEBUGP(GVNIC_INFO, "[%s] Allocating resource for tx: %u with %u descriptors",
         __FUNCTION__, id, num_descriptor_);

  if (!TxRing::Init(id, slice, traffic_class, num_descriptor,
                    /*use_raw_addressing=*/false, queue_page_list, notify_id,
                    adapter_resource, statistics, device_counters)) {
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

void TxRingQpl::Release() {
  PAGED_CODE();

  bool was_initialized = Invalidate();
  if (!was_initialized) {
    return;
  }

  CleanPendingPackets();
  FreeMemory(segment_allocated_size_);

  TxRing::Release();
}

void TxRingQpl::SendBufferList(PNET_BUFFER_LIST net_buffer_list,
                               bool is_dpc_level) {
  {
    SpinLockContext lock_context(&lock_, is_dpc_level);
    while (net_buffer_list) {
      NET_BUFFER_LIST* next_net_buffer_list =
          NET_BUFFER_LIST_NEXT_NBL(net_buffer_list);
      NET_BUFFER_LIST_NEXT_NBL(net_buffer_list) = nullptr;

      TxNetBufferList* net_packet = GetTxNetBufferList(net_buffer_list);
      if (!net_packet) {
        CompleteNetBufferListWithStatus(net_buffer_list, NDIS_STATUS_RESOURCES,
                                        is_dpc_level);
        return;
      }

#if DBG
      // Link the associated TxRing and TxNetBufferList to the net buffer so
      // that we can easily find the associated objects from a stalled or
      // corrupted net buffer. This is only used for debugging.
      NET_BUFFER* net_buffer = NET_BUFFER_LIST_FIRST_NB(net_buffer_list);
      while (net_buffer != nullptr) {
        NET_BUFFER* next_net_buffer = NET_BUFFER_NEXT_NB(net_buffer);
        net_buffer->MiniportReserved[kNetBufferTxNetBufferListIdx] = net_packet;
        net_buffer->MiniportReserved[kNetBufferTxRingIdx] = this;
        net_buffer = next_net_buffer;
      }
#endif

      InsertTailList(&packet_to_send_, &net_packet->list_entry);

      net_buffer_list = next_net_buffer_list;
    }
  }

  PNET_BUFFER_LIST nbl_completion_list = nullptr;
  NDIS_STATUS status;
  {
    SpinLockContext lock_context(&lock_, is_dpc_level);
    status = SendNetPackets(&nbl_completion_list);
  }

  if (status == NDIS_STATUS_RESOURCES) {
    // The QPL or descriptor ring is full, so check if packets can be completed
    // now and try scheduling again immediately rather than waiting for an
    // interrupt.
    if (is_dpc_level) {
      NT_ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);
      ProcessCompletePacketsWithoutCompletingNbls(&nbl_completion_list);
    } else {
      NT_ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);
      KIRQL old_irql = 0;
      NDIS_RAISE_IRQL_TO_DISPATCH(&old_irql);

      ProcessCompletePacketsWithoutCompletingNbls(&nbl_completion_list);

      NDIS_LOWER_IRQL(old_irql, DISPATCH_LEVEL);
    }
  }

  if (nbl_completion_list != nullptr) {
    CompleteNetBufferListWithStatus(nbl_completion_list, NDIS_STATUS_SUCCESS,
                                    is_dpc_level);
  }
}

void TxRingQpl::ProcessCompletePackets() {
  NT_ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

  PNET_BUFFER_LIST nbl_completion_list = nullptr;
  ProcessCompletePacketsWithoutCompletingNbls(&nbl_completion_list);
  if (nbl_completion_list != nullptr) {
    CompleteNetBufferListWithStatus(nbl_completion_list, NDIS_STATUS_SUCCESS,
                                    /*is_dpc_level=*/true);
  }
}

void TxRingQpl::ProcessCompletePacketsWithoutCompletingNbls(
    PNET_BUFFER_LIST* nbl_completion_list) {
  NT_ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

  SpinLockContext lock_context(&lock_, true);
  UINT32 packets_sent = ReadPacketsSent();
  UINT32 buffer_to_free = 0;

  while (packets_sent != num_sent_segments_) {
    UINT32 segment_idx = num_sent_segments_ & descriptor_mask_;
    buffer_to_free += segment_allocated_size_[segment_idx];
    num_sent_segments_++;
  }

  if (buffer_to_free > 0) {
    device_queue_.FreeAllocatedBuffer(buffer_to_free, lock_);
  }

  // Resources have been reclaimed, so pending net buffers can be processed.
  SendNetPackets(nbl_completion_list);

  DEBUGP(GVNIC_VERBOSE, "[%s] TxRing id - %u: requested - %u, done - %u",
         __FUNCTION__, id(), num_request_segments_, num_sent_segments_);
}

_Requires_lock_held_(lock_) NDIS_STATUS TxRingQpl::SendNetPackets(
    PNET_BUFFER_LIST* nbl_completion_list) {
  NT_ASSERT(nbl_completion_list != nullptr);
  if (current_net_buffer_to_send_ == nullptr) {
    current_net_buffer_to_send_ = GetNextNetBufferToSend(nbl_completion_list);
  }

  UINT current_num_request = num_request_segments_;

  // Send as many packets as we can until there is nothing to send or
  // driver run out of resources(descriptor or queue page list).
  NDIS_STATUS status = NDIS_STATUS_SUCCESS;
  while (current_net_buffer_to_send_ != nullptr) {
    // We don't know the exact descriptor requirement yet but check for the
    // worst case (header + 2 data segment). We have a large number of
    // descriptors so this usually won't be an issue.
    if (GetAvailableDescriptors() < 3) {
      status = NDIS_STATUS_RESOURCES;
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
        current_net_buffer_to_send_, current_net_buffer_list_to_send_->lso_info,
        lock_);
    if (packet_segment_info.allocated_length == 0) {
      // copy failed due to system resources are low or exhausted.
      // Will retry on next SendNetPackets.
      status = NDIS_STATUS_RESOURCES;
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
    current_net_buffer_to_send_ = GetNextNetBufferToSend(nbl_completion_list);
  }

  if (current_num_request != num_request_segments_) {
    WriteDoorbell(num_request_segments_);
  }

  DEBUGP(GVNIC_VERBOSE, "[%s] TxRing id - %u: requested - %u, done - %u",
         __FUNCTION__, id(), num_request_segments_, num_sent_segments_);

  return status;
}

void TxRingQpl::CleanPendingPackets() {
  SpinLockContext lock_context(&lock_, false);

  if (current_net_buffer_list_to_send_ != nullptr) {
    CompleteNetBufferListWithStatus(
        current_net_buffer_list_to_send_->net_buffer_list,
        NDIS_STATUS_RESET_IN_PROGRESS, /*is_dpc_level=*/false);
    ReturnTxNetBufferList(current_net_buffer_list_to_send_);
    current_net_buffer_list_to_send_ = nullptr;
  }

  if (IsListInitialized(packet_to_send_)) {
    while (!IsListEmpty(&packet_to_send_)) {
      TxNetBufferList* tx_net_buffer_list =
          reinterpret_cast<TxNetBufferList*>(CONTAINING_RECORD(
              RemoveHeadList(&packet_to_send_), TxNetBufferList, list_entry));
      CompleteNetBufferListWithStatus(tx_net_buffer_list->net_buffer_list,
                                      NDIS_STATUS_RESET_IN_PROGRESS,
                                      /*is_dpc_level=*/false);
      ReturnTxNetBufferList(tx_net_buffer_list);
    }
  }
}

NET_BUFFER* TxRingQpl::GetNextNetBufferToSend(
    PNET_BUFFER_LIST* nbl_completion_list) {
  NT_ASSERT(nbl_completion_list != nullptr);
  // Check whether we have next net_buffer.
  if (current_net_buffer_to_send_ != nullptr) {
    NET_BUFFER* next_net_buffer =
        NET_BUFFER_NEXT_NB(current_net_buffer_to_send_);
    if (next_net_buffer != nullptr) {
      return next_net_buffer;
    } else {
      // The current net_buffer_list is completed. Move it to a complete list.
      if (*nbl_completion_list == nullptr) {
        *nbl_completion_list =
            current_net_buffer_list_to_send_->net_buffer_list;
      } else {
        NET_BUFFER_LIST_NEXT_NBL(
            current_net_buffer_list_to_send_->net_buffer_list) =
            *nbl_completion_list;
        *nbl_completion_list =
            current_net_buffer_list_to_send_->net_buffer_list;
      }

      ReturnTxNetBufferList(current_net_buffer_list_to_send_);
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
