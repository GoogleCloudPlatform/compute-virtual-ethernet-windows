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

#include "device_fifo_queue.h"  // NOLINT: include directory

#include <ndis.h>

#include "abi.h"    // NOLINT: include directory
#include "trace.h"  // NOLINT: include directory
#include "utils.h"  // NOLINT: include directory

#include "device_fifo_queue.tmh"  // NOLINT: trace message header

namespace {
// Query mdl length and address.
// Out:
//  - mdl_len
//  - mdl_addr
bool QueryMdl(MDL* mdl, UINT32* mdl_len, void** mdl_addr) {
  NdisQueryMdl(
      mdl, mdl_addr, mdl_len,
      static_cast<MM_PAGE_PRIORITY>(LowPagePriority | MdlMappingNoExecute));

  if (mdl_addr == nullptr) {
    DEBUGP(GVNIC_WARNING, "[%s] WARNING:  Fail to get the mdl address.",
           __FUNCTION__);
    return false;
  }

  return true;
}
}  // namespace

void DeviceFifoQueue::Init(PVOID* pages, UINT32 page_count) {
  head_ = 0;
  NT_ASSERT(page_count <= MAXUINT32 / PAGE_SIZE);
  total_size_bytes_ = available_bytes_ = page_count * PAGE_SIZE;
  pages_ = pages;
  page_count_ = page_count;
}

UINT32 DeviceFifoQueue::GetTailPaddings(UINT32 allocate_bytes) {
  return (head_ + allocate_bytes < total_size_bytes_)
             ? 0
             : total_size_bytes_ - head_;
}

// clang-format off
bool DeviceFifoQueue::CalculateNetBufferLengths(const NET_BUFFER& net_buffer,
                                          void** header_addr,
                                          UINT32* header_len,
                                          UINT32* tail_padding,
                                          UINT32* header_cache_line_padding,
                                          MDL** data_mdl_addr,
                                          UINT32* data_len,
                                          UINT32* data_cache_line_padding) {
  // clang-format on
  UINT32 packet_len = NET_BUFFER_DATA_LENGTH(&net_buffer);

  // Load detail header mdl length, offset, address
  MDL* header_mdl = NET_BUFFER_CURRENT_MDL(&net_buffer);
  UINT32 header_mdl_offset = NET_BUFFER_CURRENT_MDL_OFFSET(&net_buffer);
  UINT32 header_mdl_len;
  void* header_mdl_addr = nullptr;
  if (!QueryMdl(header_mdl, &header_mdl_len, &header_mdl_addr)) {
    return false;
  }

  // All data required for header segment.
  *header_addr = OffsetToPointer(header_mdl_addr, header_mdl_offset);
  *header_len = header_mdl_len - header_mdl_offset;
  *tail_padding = GetTailPaddings(*header_len);
  *header_cache_line_padding =
      GetCacheAlignOffset(*header_len + *tail_padding, kCacheLineSize);

  // All data required for data segment.
  *data_mdl_addr = header_mdl->Next;
  *data_len = packet_len - *header_len;
  *data_cache_line_padding = GetCacheAlignOffset(*data_len, kCacheLineSize);

  return true;
}

void DeviceFifoQueue::AdvanceHead(UINT32 offset) {
  if (offset == 0) {
    return;
  }

  NT_ASSERT(head_ + offset <= total_size_bytes_);
  head_ += offset;
  if (head_ == total_size_bytes_) {
    head_ = 0;
  }
}

_Requires_lock_held_(lock) PacketSegmentInfo DeviceFifoQueue::CopyNetBuffer(
    NET_BUFFER* net_buffer, bool is_lso, NDIS_SPIN_LOCK& lock) {
  UNREFERENCED_PARAMETER(lock);  // Used for SAL lock check only.
  PacketSegmentInfo packet_segment_info;
  UINT32 original_head = head_;  // Record the current head in case of rollback.
  UINT32 packet_allocated_size = 0;

  if (is_lso) {
    packet_allocated_size = CopyLsoPacket(net_buffer, &packet_segment_info);
  } else {
    packet_allocated_size = CopyNormalPacket(net_buffer, &packet_segment_info);
  }

  // Reset the header if anything goes wrong.
  if (packet_allocated_size == 0) {
    head_ = original_head;
    packet_segment_info.allocated_length = 0;
    return packet_segment_info;
  }

  // Verify the head_ is still cache line aligned.
  NT_ASSERT(head_ % kCacheLineSize == 0);

#if DBG
  // Verify the actual allocated size is same as the number calculated.
  UINT32 total_allocated_size = 0;
  if (head_ < original_head) {
    // This means head gets reset to zero during process.
    total_allocated_size = total_size_bytes_ - original_head + head_;
  } else {
    total_allocated_size = head_ - original_head;
  }
  NT_ASSERT(total_allocated_size == packet_allocated_size);
#endif

  available_bytes_ -= packet_allocated_size;

  DEBUGP(GVNIC_VERBOSE,
         "[%s] packet_allocated_size - %u, segment - %u, "
         "available_bytes_ - %u, total_bytes_ - %u",
         __FUNCTION__, packet_allocated_size,
         packet_segment_info.data_segment_count + 1, available_bytes_,
         total_size_bytes_);
  return packet_segment_info;
}

// Copy net packet into queue. Since normal packet size is limited by MTU,
// driver can offer to save cost on splitting the packets if there is not
// enough space at the end. The logic always use one segment only and copy
// the entire packet into continues address block.
// For diagram:
//  CP -> Cache line Padding
//  TP -> Tail padding.
//
// Case 1 - For normal case where there is enough space left in the queue:
// +-----+-------------------------+----+-----+
// | ... | Header + Data payload   | CP | ... |
// +-----+-------------------------+----+-----+
//
// Case 2 - Don't have enough space to hold the header at tail, add tail
// padding and copy the whole packet to the start of the queue:
// +-----------------------+----+--------+----+
// | Header + Data payload | CP | ...... | TP |
// +-----------------------+----+--------+----+
int DeviceFifoQueue::CopyNormalPacket(NET_BUFFER* net_buffer,
                                      PacketSegmentInfo* packet_segment_info) {
  UINT32 packet_size = NET_BUFFER_DATA_LENGTH(net_buffer);
  UINT32 tail_padding = GetTailPaddings(packet_size);
  UINT32 cache_line_padding = GetCacheAlignOffset(packet_size, kCacheLineSize);
  UINT32 packet_allocated_size =
      packet_size + tail_padding + cache_line_padding;

  if (packet_allocated_size > available_bytes_) {
    DEBUGP(GVNIC_WARNING,
           "[%s] WARNING: not enough space - available %#X - request %#llX",
           __FUNCTION__, available_bytes_, packet_allocated_size);
    return 0;
  }

  // Add tail padding in case 2.
  AdvanceHead(tail_padding);

  // Record packet offset/length.
  packet_segment_info->packet_offset = head_;
  packet_segment_info->packet_length = packet_size;
  packet_segment_info->allocated_length = packet_allocated_size;
  packet_segment_info->data_segment_count = 0;

  // Copy data
  UINT32 byte_copied = 0;
  ULONG current_offset = NET_BUFFER_CURRENT_MDL_OFFSET(net_buffer);

  for (MDL* current_mdl = NET_BUFFER_CURRENT_MDL(net_buffer);
       current_mdl != nullptr && byte_copied < packet_size;
       current_mdl = current_mdl->Next) {
    void* mdl_addr = nullptr;
    UINT32 mdl_len;
    if (!QueryMdl(current_mdl, &mdl_len, &mdl_addr)) {
      return 0;
    }

    UINT32 copy_len = min(mdl_len - current_offset, packet_size - byte_copied);
    CopyBytesToHead(OffsetToPointer(mdl_addr, current_offset), copy_len);
    byte_copied += copy_len;

    current_offset = 0;  // only the first MDL has data offset.
  }

  // Add data cache line padding.
  AdvanceHead(cache_line_padding);

  return packet_allocated_size;
}

// Copy LSO packet into FIFO queue. Since the LSO packets can be very large
// and we don't want to waste space at the tail, the logic copy the packet
// into up to 3 segments. We never split header but could split data payload
// into 2 segments. Here are the different scenarios:
// For diagram:
//  CP -> Cache line Padding
//  TP -> Tail padding.
//
// Case 1 - For normal case where there is enough space left in the queue:
// +-----+--------+----+--------------+----+-----+
// | ... | Header | CP | Data payload | CP | ... |
// +-----+--------+----+--------------+----+-----+
//
// Case 2 - Don't have enough space to hold the header at tail, add tail
// padding and copy the Header to the start of the queue:
// +--------+----+--------------+----+--------+----+
// | Header | CP | Data payload | CP | ...... | TP |
// +--------+----+--------------+----+--------+----+
//
// Case 3 - We have enough space at tail for header but not for data payload,
// in this scenario, we split data payload into two:
// +------------------+----+--------+--------+----+------------------+
// | Data payload - 2 | CP | ...... | Header | CP | Data payload - 1 |
// +------------------+----+--------+--------+----+------------------+
int DeviceFifoQueue::CopyLsoPacket(NET_BUFFER* net_buffer,
                                   PacketSegmentInfo* packet_segment_info) {
  UINT32 header_len, tail_padding, header_cache_line_padding;
  UINT32 data_len, data_cache_line_padding;
  void* header_addr;
  MDL* data_mdl_addr;

  // Calculate header and data segment addr/length.
  if (!CalculateNetBufferLengths(*net_buffer, &header_addr, &header_len,
                                 &tail_padding, &header_cache_line_padding,
                                 &data_mdl_addr, &data_len,
                                 &data_cache_line_padding)) {
    return 0;
  }

  // Get overall packet allocated size inside FIFO queue.
  UINT32 packet_allocated_size = header_len + tail_padding +
                                 header_cache_line_padding + data_len +
                                 data_cache_line_padding;

  // Make sure we have enough space, otherwise, reject the request.
  if (packet_allocated_size > available_bytes_) {
    DEBUGP(GVNIC_WARNING,
           "[%s] WARNING: not enough space - available %#X - request %#llX",
           __FUNCTION__, available_bytes_, packet_allocated_size);
    return 0;
  }

  // Add tail padding in case 2.
  AdvanceHead(tail_padding);

  // Copy the packet header:
  CopyHeaderSegment(header_addr, header_len,
                    tail_padding + header_cache_line_padding,
                    packet_segment_info);

  // Add header cache line padding.
  AdvanceHead(header_cache_line_padding);

  // Copy data packets and split it into two if needed.
  if (!CopyDataSegment(data_mdl_addr, data_len, data_cache_line_padding,
                       packet_segment_info)) {
    return 0;
  }

  // Add data cache line padding.
  AdvanceHead(data_cache_line_padding);
  return packet_allocated_size;
}

void DeviceFifoQueue::CopyHeaderSegment(
    void* header_addr, UINT32 header_len, UINT32 header_padding_len,
    PacketSegmentInfo* packet_segment_info) {
  packet_segment_info->packet_length = header_len;
  packet_segment_info->packet_offset = head_;
  packet_segment_info->allocated_length = header_len + header_padding_len;
  CopyBytesToHead(header_addr, header_len);
}

bool DeviceFifoQueue::CopyDataSegment(MDL* data_mdl, UINT32 data_len,
                                      UINT32 data_cacheline_padding,
                                      PacketSegmentInfo* packet_segment_info) {
  if (data_mdl == nullptr) {
    packet_segment_info->data_segment_count = 0;
    return true;
  }

  UINT32 tail_space = total_size_bytes_ - head_;
  if (data_len <= tail_space) {
    // For CopyNetBuffer case 1 and 2.
    packet_segment_info->data_segment_count = 1;
    packet_segment_info->data_segment_info[0].offset = head_;
    packet_segment_info->data_segment_info[0].length = data_len;
    packet_segment_info->data_segment_info[0].allocated_length =
        data_len + data_cacheline_padding;
  } else {
    // For CopyNetBuffer case 3.
    packet_segment_info->data_segment_count = 2;
    packet_segment_info->data_segment_info[0].offset = head_;
    packet_segment_info->data_segment_info[0].length = tail_space;
    packet_segment_info->data_segment_info[0].allocated_length =
        packet_segment_info->data_segment_info[0].length;
    packet_segment_info->data_segment_info[1].offset = 0;
    packet_segment_info->data_segment_info[1].length = data_len - tail_space;
    packet_segment_info->data_segment_info[1].allocated_length =
        packet_segment_info->data_segment_info[1].length +
        data_cacheline_padding;
  }

  UINT32 byte_copied = 0;
  for (MDL* current_mdl = data_mdl;
       current_mdl != nullptr && byte_copied < data_len;
       current_mdl = current_mdl->Next) {
    void* mdl_addr = nullptr;
    UINT32 mdl_len;
    if (!QueryMdl(current_mdl, &mdl_len, &mdl_addr)) {
      return false;
    }

    ULONG copy_len = min(mdl_len, data_len - byte_copied);
    if (copy_len + head_ <= total_size_bytes_) {
      CopyBytesToHead(mdl_addr, copy_len);
    } else {
      // Special handle for case 3.
      UINT32 tail_segment_size = total_size_bytes_ - head_;
      CopyBytesToHead(mdl_addr, tail_segment_size);
      CopyBytesToHead(OffsetToPointer(mdl_addr, tail_segment_size),
                      copy_len - tail_segment_size);
    }

    byte_copied += copy_len;
  }

  return true;
}

_Requires_lock_held_(lock) void DeviceFifoQueue::FreeAllocatedBuffer(
    UINT32 length, NDIS_SPIN_LOCK& lock) {
  UNREFERENCED_PARAMETER(lock);  // Used for SAL lock check only.
  NT_ASSERT(available_bytes_ + length <= total_size_bytes_);
  available_bytes_ += length;
  DEBUGP(GVNIC_VERBOSE,
         "[%s] free_packet_size - %u, available_bytes_ - %u, total_bytes_ - %u",
         __FUNCTION__, length, available_bytes_, total_size_bytes_);
}

void DeviceFifoQueue::CopyBytesToHead(void* source, UINT32 len) {
  UINT32 copied_bytes = 0;
  while (copied_bytes != len) {
    UINT32 page_list_idx = head_ / PAGE_SIZE;
    UINT32 current_offset = head_ % PAGE_SIZE;
    UINT32 max_copy_size = PAGE_SIZE - current_offset;
    UINT32 to_copy = min(max_copy_size, (len - copied_bytes));
    NT_ASSERT(page_list_idx < page_count_);
    NdisMoveMemory(OffsetToPointer(pages_[page_list_idx], current_offset),
                   OffsetToPointer(source, copied_bytes), to_copy);

    AdvanceHead(to_copy);
    copied_bytes += to_copy;
  }
  NT_ASSERT(copied_bytes == len);
}
