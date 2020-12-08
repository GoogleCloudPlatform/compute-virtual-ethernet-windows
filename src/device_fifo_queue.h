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

#ifndef FIFO_QUEUE_H_
#define FIFO_QUEUE_H_

#include <ndis.h>

#include "queue_page_list.h"  // NOLINT: include directory

// Used to pass the fragmentation info between tx_ring and fifo_queue.
// Please see CopyNetBuffer for details.
struct PacketSegmentInfo {
  struct DataSegmentInfo {
    UINT32 offset;
    UINT32 length;
    // length + any paddings.
    UINT32 allocated_length;
  };
  UINT64 packet_offset;
  UINT32 packet_length;
  // Pakcet_length + any paddings.
  UINT32 allocated_length;
  UINT8 data_segment_count;
  DataSegmentInfo data_segment_info[2];
};

// Class represent a FIFO queue in the gVnice Device.
//
// Driver copy packet into the queue and device will sent out the packets in
// this queue with first-in-first-out sequence. TxRing call
// CopyNetBuffer/FreeAllocatedBuffer while maintain the order to match the
// device behavior. FIFOQueue itself doesn't track the order but just handle
// allocate/release bytes from the QueuePageList.
//
// The class operate on a list of pages allocated from the QueuePageList.
//
// head_ always point to where the next packet should get copied to. The packet
// block can across the boundary of pages but can not cross the end of the
// list. If we cannot fit the data in the end, we skip all the space left and
// start from the beginning.
//
// Availble_bytes_ keeps trace of how many space left in the queue so we never
// overwrite in-use-space. It gets decreased when package copied into the queue
// and increased when device tells the driver the packet is sent.
//
// Note: Operations on this class is not thread safe. Be sure to allow one core
// to access the page list at a time.
class DeviceFifoQueue final {
 public:
  DeviceFifoQueue()
      : pages_(nullptr), total_size_bytes_(0), available_bytes_(0), head_(0) {}
  ~DeviceFifoQueue() = default;

  // Not copyable or movable
  DeviceFifoQueue(const DeviceFifoQueue&) = delete;
  DeviceFifoQueue& operator=(const DeviceFifoQueue&) = delete;

  // DeviceFifoQueue get a point to pages inside queue_page_list and operation
  // on that list.
  void Init(PVOID* pages, UINT32 page_count);

  // Copy mdls inside the net_buffer into head of FIFO queue.
  // Return segment info for how/where the packet is copied into.
  // Params:
  // - net_buffer[in]: point to the NET_BUFFER object to copy from.
  // - is_lso: if it is a large send offload packet. If true, the packet might
  //      get split up to 3 segments.
  //
  // Method is not concurrent safe and caller tx_ring need to hold appropriate
  // lock.
  _Requires_lock_held_(lock) PacketSegmentInfo
      CopyNetBuffer(NET_BUFFER* net_buffer, bool is_lso, NDIS_SPIN_LOCK& lock);

  // Free used space allocated by CopyNetBuffer (size from allocated_length
  // inside PacketSegmentInfo). It marks the bytes allocated
  // by the segment to be available and ready to take new net packets.
  _Requires_lock_held_(lock) void FreeAllocatedBuffer(UINT32 length,
                                                      NDIS_SPIN_LOCK& lock);

 private:
  // Copy raw memory bits into where the head_ points to and also move the
  // head_ to next copy position.
  void CopyBytesToHead(void* source, UINT32 len);

  // Return padding required if the allocated_byte cannot fit in the available
  // space by the end of the queue. Return 0 otherwise.
  UINT32 GetTailPaddings(UINT32 allocate_bytes);

  // Copy header MDL into queue and update segment info.
  void CopyHeaderSegment(void* header_addr, UINT32 header_len,
                         UINT32 header_padding_len,
                         PacketSegmentInfo* packet_segment_info);

  // Copy Data MDLs into queue and update segment info for where and how the
  // overall packet is stored.
  // Return false if copy failed.
  bool CopyDataSegment(MDL* data_mdl, UINT32 data_len,
                       UINT32 data_cacheline_padding,
                       PacketSegmentInfo* packet_segment_info);

  // Calculate header, data segment address/length/padding based on net_buffer.
  // Return false if map net_buffer failed.
  // clang-format off
  bool CalculateNetBufferLengths(const NET_BUFFER& net_buffer,
                                 void** header_addr,
                                 UINT32* header_len,
                                 UINT32* tail_padding,
                                 UINT32* header_cache_line_padding,
                                 MDL** data_mdl_addr,
                                 UINT32* data_len,
                                 UINT32* data_cache_line_padding);
  // clang-format on

  // Copy normal net packets into queue. The whole packet will always get
  // copied into a continuous block space and never gets split.
  // Return the total number of bytes used. Return 0 if failed.
  int CopyNormalPacket(NET_BUFFER* net_buffer,
                       PacketSegmentInfo* packet_segment_info);

  // Copy LSO packets into queue. The packet will get copied up to 3 segments.
  // Return the total number of bytes used. Return 0 if failed.
  int CopyLsoPacket(NET_BUFFER* net_buffer,
                    PacketSegmentInfo* packet_segment_info);

  // Move head_ by offset. Go back to 0 if it reaches the end exactly.
  // offset should never go beyond the end and will cause crash.
  void AdvanceHead(UINT32 offset);

  PVOID* pages_;
  UINT32 page_count_;
  // Total size of DeviceFifoQueue in bytes.
  UINT32 total_size_bytes_;
  UINT32 available_bytes_;

  // Point to the next copy position.
  UINT32 head_;
};
#endif  // FIFO_QUEUE_H_
