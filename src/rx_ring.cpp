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

#include "rx_ring.h"  // NOLINT: include directory

#include <ndis.h>

#include "abi.h"                 // NOLINT: include directory
#include "adapter_statistics.h"  // NOLINT: include directory
#include "device_parameters.h"   // NOLINT: include directory
#include "packet_assembler.h"    // NOLINT: include directory
#include "ring_base.h"           // NOLINT: include directory
#include "rx_packet.h"           // NOLINT: include directory
#include "rx_ring_entry.h"       // NOLINT: include directory
#include "spin_lock_context.h"   // NOLINT: include directory
#include "trace.h"               // NOLINT: include directory
#include "utils.h"               // NOLINT: include directory

#include "rx_ring.tmh"  // NOLINT: trace message header

namespace {
// Special number picked by device to help identify whether the packet should be
// be processed.
constexpr int kSeqPrimeNumber = 7;

// Max packet size driver can process async.
constexpr int kMaxAsyncPacketSize = PAGE_SIZE / 2;

// Mask use to flip the point to the first half and second half of the page.
constexpr UINT32 kDataRingFlipMask = PAGE_SIZE / 2;

// We have enough notification blocks to tx_max and rx_max. So we start rx
// notify block from tx_num_slices.
inline UINT GetRxNotifyBlockId(UINT tx_num_slices, UINT id) {
  return tx_num_slices + id;
}

// Return the sequence number from flags_sequence field inside rx descriptor.
UINT32 GetSequenceNumber(UINT16 flags_sequence) {
  return RtlUshortByteSwap(flags_sequence) & 0x7;
}

// Return the next value in range [1, kSeqPrimeNumber].
UINT32 GetNextSequenceNumber(UINT32 seq_number) {
  return seq_number == kSeqPrimeNumber ? 1 : seq_number + 1;
}

// Point the rx data ring offset to unused location.
// For now, driver just flip the offset between first and second half of the
// memory page. In the future, it can be extended to smartly move the offset to
// unused buffer.
void AdjustRxDataRingOffset(UINT64 current_offset,
                            RxDataRingSlot* rx_data_ring) {
  UINT64 new_offset = current_offset ^ kDataRingFlipMask;
  rx_data_ring->queue_page_list_offset = RtlUlonglongByteSwap(new_offset);
}
}  // namespace

RxRing::~RxRing() {
  PAGED_CODE();
  Release();
}

bool RxRing::Init(UINT32 id, UINT32 slice, UINT32 traffic_class,
                  UINT32 num_descriptor, QueuePageList* queue_page_list,
                  UINT32 notify_id, AdapterResources* adapter_resource,
                  AdapterStatistics* statistics,
                  const DeviceCounter* device_counters) {
  PAGED_CODE();

  // num_descriptor is expected to be power of 2.
  NT_ASSERT((num_descriptor & (num_descriptor - 1)) == 0);

  num_descriptor_ = num_descriptor;
  descriptor_mask_ = num_descriptor_ - 1;
  packet_seq_number_ = 1;
  checksum_offload_enabled_ = false;
  rss_enabled_ = false;
  rss_hash_function_ = 0;
  rss_hash_type_ = 0;
  NdisAllocateSpinLock(&seq_counter_spin_lock_);

  // The current implementation requires that we have one descriptor per page.
  NT_ASSERT(num_descriptor_ == queue_page_list->num_pages());

  DEBUGP(GVNIC_INFO, "[%s] Allocating resource for rx: %u with %u slots",
         __FUNCTION__, id, num_descriptor_);

  if (!RingBase::Init(id, slice, traffic_class, queue_page_list, notify_id,
                      adapter_resource, statistics, device_counters)) {
    return false;
  }

  if (!descriptor_ring_.Allocate(adapter_resource->miniport_handle(),
                                 num_descriptor_)) {
    DEBUGP(GVNIC_ERROR,
           "[%s] ERROR: Memory allocation failed for rx descriptor ring",
           __FUNCTION__);
    return false;
  }

  if (!data_ring_.Allocate(adapter_resource->miniport_handle(),
                           num_descriptor_)) {
    DEBUGP(GVNIC_ERROR, "[%s] ERROR: Memory allocation failed for rx data ring",
           __FUNCTION__);
    return false;
  }

  rx_ring_entries_ = AllocateMemory<RxRingEntry>(
      adapter_resource->miniport_handle(), num_descriptor_);

  if (rx_ring_entries_ == nullptr) {
    return false;
  }

  if (!InitRxEntries(adapter_resource->net_buffer_list_pool(),
                     adapter_resource->miniport_handle())) {
    return false;
  }

  return true;
}

void RxRing::UpdateRssConfig(const RSSConfiguration& rss_config) {
  rss_enabled_ = rss_config.is_enabled();
  rss_hash_function_ = rss_config.hash_func();
  rss_hash_type_ = rss_config.hash_type();
#ifdef DBG
  rss_secret_key_ = rss_config.hash_secret_key();
#endif
}

bool RxRing::InitRxEntries(NDIS_HANDLE pool_handle,
                           NDIS_HANDLE miniport_handle) {
  for (UINT i = 0; i < num_descriptor_; i++) {
    rx_ring_entries_[i].descriptor = descriptor_ring_.virtual_address() + i;
    rx_ring_entries_[i].data = data_ring_.virtual_address() + i;
    rx_ring_entries_[i].data->queue_page_list_offset =
        RtlUlonglongByteSwap(i * PAGE_SIZE);
    rx_ring_entries_[i].pending_count = 0;

    // First half of the page.
    rx_ring_entries_[i].packet_addr[0] =
        OffsetToPointer(queue_page_list()->pages()[i], kPacketHeaderPadding);
    rx_ring_entries_[i].eth_header[0] =
        reinterpret_cast<ETH_HEADER*>(rx_ring_entries_[i].packet_addr[0]);
    rx_ring_entries_[i].ipv4_header[0] = reinterpret_cast<IPv4Header*>(
        OffsetToPointer(rx_ring_entries_[i].eth_header[0], sizeof(ETH_HEADER)));
    rx_ring_entries_[i].net_buffer_lists[0] =
        NdisAllocateNetBufferAndNetBufferList(
            pool_handle, /*ContextSize=*/0, /*ContextBackFill=*/0,
            /*MdlChain=*/nullptr, /*DataOffset=*/0, /*DataLength=*/0);
    if (rx_ring_entries_[i].net_buffer_lists[0] == nullptr) {
      DEBUGP(GVNIC_ERROR, "[%s] ERROR: Fail to allocate NET_BUFFER_LIST.",
             __FUNCTION__);
      return false;
    }

    // Second half of the page.
    rx_ring_entries_[i].packet_addr[1] = OffsetToPointer(
        queue_page_list()->pages()[i], kPacketHeaderPadding + PAGE_SIZE / 2);
    rx_ring_entries_[i].eth_header[1] =
        reinterpret_cast<ETH_HEADER*>(rx_ring_entries_[i].packet_addr[1]);
    rx_ring_entries_[i].ipv4_header[1] = reinterpret_cast<IPv4Header*>(
        OffsetToPointer(rx_ring_entries_[i].eth_header[1], sizeof(ETH_HEADER)));
    rx_ring_entries_[i].net_buffer_lists[1] =
        NdisAllocateNetBufferAndNetBufferList(
            pool_handle, /*ContextSize=*/0, /*ContextBackFill=*/0,
            /*MdlChain=*/nullptr, /*DataOffset=*/0, /*DataLength=*/0);
    if (rx_ring_entries_[i].net_buffer_lists[1] == nullptr) {
      DEBUGP(GVNIC_ERROR, "[%s] ERROR: Fail to allocate NET_BUFFER_LIST.",
             __FUNCTION__);
      return false;
    }

    for (auto& net_buffer_list : rx_ring_entries_[i].net_buffer_lists) {
      net_buffer_list->SourceHandle = miniport_handle;
      net_buffer_list->Status = NDIS_STATUS_SUCCESS;
    }

    rx_ring_entries_[i].rsc_next = nullptr;
    rx_ring_entries_[i].rsc_last = nullptr;
  }

  return true;
}

void RxRing::Release() {
  PAGED_CODE();
  for (UINT i = 0; i < num_descriptor_; i++) {
    for (auto& net_buffer_list : rx_ring_entries_[i].net_buffer_lists) {
      if (net_buffer_list != nullptr) {
        NdisFreeNetBufferList(net_buffer_list);
        net_buffer_list = nullptr;
      }
    }
  }

  FreeMemory(rx_ring_entries_);
  rx_ring_entries_ = nullptr;

  data_ring_.Release();
  descriptor_ring_.Release();
  RingBase::Release();
}

void RxRing::SetInitFreeSlot() {
  // packet_counter starts with num_descriptors_.
  // The way device figure out how many slot has been process is do a diff
  // between new doorbell and the old value, with init value 0.
  //
  // On init, we report num_descriptor_ so device knows that all slots are free.
  //
  // As a side affect, our packet_counter also needs to start with
  // num_descriptors_ so when new packets is processed and the increased counter
  // gets pushed to device, it get the correct delta.
  packet_counter_ = num_descriptor_;
  WriteDoorbell(num_descriptor_);
}

bool RxRing::ProcessPendingPackets(bool is_dpc_level,
                                   PacketAssembler* packet_assembler) {
  NT_ASSERT(packet_assembler != nullptr);
  SpinLockContext lock_context(&seq_counter_spin_lock_, is_dpc_level);

  UINT32 packet_idx = packet_counter_ & descriptor_mask_;
  UINT32 current_packet_counter = packet_counter_;

  RxRingEntry* cur_entry = rx_ring_entries_ + packet_idx;
  RxDescriptor* cur_desc = cur_entry->descriptor;

  // Assume we can process all packets by default.
  bool is_all_packet_processed = true;

  // The way we detect new packets in rx_ring is as follows:
  // We have a 3 bit fields in flags_sequence of rx descriptor. This field
  // increments from 1 to 7 each time device writes an new Entry, and then wraps
  // back to 1. Driver keeps track of the next expected sequence number and
  // compare it with the sequence number from the descriptor. If it matches,
  // this is a new packet.
  //
  // The algorithm works because the number of descriptor is power of 2 and can
  // not be multiple of 7. So when device reuse the same descriptor, it is
  // guaranteed that the sequence number will be different.
  while (GetSequenceNumber(cur_desc->flags_sequence) == packet_seq_number_) {
    if (!packet_assembler->CanAllocateNBL()) {
      DEBUGP(GVNIC_VERBOSE, "[%s]: reach max net_buffer_list to indicate.",
             __FUNCTION__);
      is_all_packet_processed = false;
      break;
    }
    RxPacket rx_packet{*cur_entry};

    if (checksum_offload_enabled_) {
      rx_packet.SetChecksumInfo();
    }

    if (rss_enabled_) {
#ifdef DBG
      rx_packet.SetSecretKey(rss_secret_key_);
#endif
      rx_packet.SetRssInfo(RtlUlongByteSwap(cur_desc->rss_hash), rss_hash_type_,
                           rss_hash_function_);
    }

    // Currently, we only allow one pending packet at max.
    NT_ASSERT(cur_entry->pending_count < 2 && cur_entry->pending_count >= 0);
    if (rx_packet.packet_length() < kMaxAsyncPacketSize &&
        cur_entry->pending_count == 0) {
      // If there is no pending packets on current data page, we flip the
      // data pointer to the other half of the page and let OS handle the packet
      // asynchronously to reduce data copy.
      // Driver has a fairly large number of pages so most likely, packets will
      // be processed in async way.
      AdjustRxDataRingOffset(rx_packet.queue_page_list_offset(),
                             cur_entry->data);

      NET_BUFFER_LIST* net_buffer_list =
          packet_assembler->ProcessAsyncPacket(&rx_packet);
      if (net_buffer_list == nullptr) {
        is_all_packet_processed = false;
        break;
      }
      IncreaseRxDataRingPendingCount(cur_entry, net_buffer_list);
    } else {
      // Cannot flip the pointer and just process it synchronously.
      if (packet_assembler->ProcessSyncPacket(&rx_packet) == nullptr) {
        is_all_packet_processed = false;
        break;
      }
    }

    packet_counter_ += 1;
    packet_idx = packet_counter_ & descriptor_mask_;
    cur_entry = rx_ring_entries_ + packet_idx;
    cur_desc = cur_entry->descriptor;
    packet_seq_number_ = GetNextSequenceNumber(packet_seq_number_);
  }

  if (current_packet_counter != packet_counter_) {
    WriteDoorbell(packet_counter_);
  }

  DEBUGP(GVNIC_VERBOSE,
         "[%s] RxRing id - %u: packet_counter - %u, seq_number - %u, all "
         "packets processed - %u",
         __FUNCTION__, id(), packet_counter_, packet_seq_number_,
         is_all_packet_processed);

  return is_all_packet_processed;
}
