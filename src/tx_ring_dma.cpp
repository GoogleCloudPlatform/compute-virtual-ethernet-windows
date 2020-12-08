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

#include "tx_ring_dma.h"  // NOLINT: include directory

#include <ndis.h>

#include "abi.h"                 // NOLINT: include directory
#include "adapter_resource.h"    // NOLINT: include directory
#include "adapter_statistics.h"  // NOLINT: include directory
#include "admin_queue.h"         // NOLINT: include directory
#include "netutils.h"            // NOLINT: include directory
#include "spin_lock_context.h"   // NOLINT: include directory
#include "trace.h"               // NOLINT: include directory
#include "tx_net_buffer.h"       // NOLINT: include directory
#include "tx_net_buffer_list.h"  // NOLINT: include directory
#include "utils.h"               // NOLINT: include directory

#include "tx_ring_dma.tmh"       // NOLINT: trace message header

namespace {

// Configuration for the buffer sizes in the buffer pool. These buffers are
// used to ensure that the packet descriptor in non-TSO packets is large enough
// for our on-host virtual switch, and to consolidate descriptors when there
// are more segments than the NIC can handle.
constexpr UINT32 kSmallBufferSizeBytes = kBytesRequiredInTxPacketDescriptor;
constexpr UINT32 kMediumBufferSizeBytes = 512;
constexpr UINT32 kLargeBufferSizeBytes = 4096;
constexpr UINT32 kEnormousBufferSizeBytes = kMaxPacketSize;

// We scale the number of buffers of each size in the buffer pool by dividing
// the descriptor count by a factor. The more descriptors in the ring, the
// more of each size of buffer. We only ever have one enormous buffer per ring.
constexpr UINT32 kSmallBufferFactor = 8;
constexpr UINT32 kMediumBufferFactor = 32;
constexpr UINT32 kLargeBufferFactor = 64;

static_assert(
    kSmallBufferSizeBytes >= kBytesRequiredInTxPacketDescriptor,
    "The smallest buffer size must be large enough to fit the number of "
    "bytes our on-host virtual switch requires in the first descriptor.");
static_assert(
    kEnormousBufferSizeBytes <= kMaxPacketSize,
    "The largest buffer cannot be larger than the maximum packet size.");

UINT GetNetBufferCount(const NET_BUFFER_LIST& net_buffer_list) {
  UINT count = 0;
  NET_BUFFER* net_buffer = NET_BUFFER_LIST_FIRST_NB(&net_buffer_list);
  while (net_buffer != nullptr) {
    count++;
    net_buffer = NET_BUFFER_NEXT_NB(net_buffer);
  }
  return count;
}

// Copies data from a net buffer's MDL chain into a shared memory buffer.
// Returns false if this function cannot get an MDL's virtual address.
bool CopyDataFromMdlChainToBuffer(const PMDL first_mdl,
                                  UINT32 offset_into_first_mdl,
                                  UINT32 bytes_to_buffer,
                                  SharedMemory<UCHAR>* destination) {
  UCHAR* buffer = destination->virtual_address();
  NT_ASSERT(buffer != nullptr);

  UINT32 buffer_used = 0;
  for (MDL* mdl = first_mdl; mdl != nullptr && buffer_used < bytes_to_buffer;
       mdl = mdl->Next) {
    PVOID virtual_addr;
    UINT32 virtual_addr_len;
    NdisQueryMdl(mdl, &virtual_addr, &virtual_addr_len,
                 static_cast<MM_PAGE_PRIORITY>(NormalPagePriority |
                                               MdlMappingNoExecute));
    if (virtual_addr == nullptr) {
      DEBUGP(GVNIC_ERROR,
             "[%s] ERROR: Failed to get an MDL's virtual address when "
             "trying to buffer data.",
             __FUNCTION__);
      return false;
    }

    const UINT32 copy_length = min(virtual_addr_len - offset_into_first_mdl,
                                   bytes_to_buffer - buffer_used);
    NdisMoveMemory(OffsetToPointer(buffer, buffer_used),
                   OffsetToPointer(virtual_addr, offset_into_first_mdl),
                   copy_length);

    buffer_used += copy_length;
    offset_into_first_mdl = 0;
  }

  return true;
}

// Wrapper to copy the last X bytes from an MDL chain into a shared memory
// buffer.
bool CopyTailDataFromMdlChainToBuffer(const NET_BUFFER* net_buffer,
                                      UINT32 bytes_from_end,
                                      SharedMemory<UCHAR>* destination) {
  UINT32 offset = NET_BUFFER_CURRENT_MDL_OFFSET(net_buffer) +
                  NET_BUFFER_DATA_LENGTH(net_buffer) - bytes_from_end;
  MDL* mdl = NET_BUFFER_CURRENT_MDL(net_buffer);
  while (mdl != nullptr) {
    if (MmGetMdlByteCount(mdl) < offset) {
      offset -= MmGetMdlByteCount(mdl);
      mdl = mdl->Next;
    } else {
      break;
    }
  }

  return CopyDataFromMdlChainToBuffer(mdl, offset, bytes_from_end, destination);
}

// Sums the number of bytes in the scatter gather elements between the
// provided indices. Count is inclusive of the first index and exclusive of
// the last.
UINT32 CountBytesInSGElements(UINT32 index_from, UINT32 index_to,
                              const SCATTER_GATHER_LIST& scatter_gather_list) {
  UINT32 sum = 0;
  while (index_from < index_to) {
    sum += scatter_gather_list.Elements[index_from].Length;
    index_from++;
  }
  return sum;
}

bool IsFailedTxNetBufferList(const TxNetBufferList& tx_nbl) {
  return tx_nbl.status != NDIS_STATUS_SUCCESS;
}

void ReportNetBufferSentWithoutCompletion(TxNetBufferList* tx_net_buffer_list,
                                          PNET_BUFFER_LIST* nbl) {
  // If all net buffers are sent, prepend the net buffer list to a net buffer
  // list chain so that these can all be completed in a single framework call.
  // The relative ordering of the net buffer lists is unimportant.
  //
  // Each net buffer list chain is thread local, so mutating the chain is
  // thread safe.
  if (InterlockedIncrement(&tx_net_buffer_list->num_sent_net_buffer) ==
      tx_net_buffer_list->num_net_buffer) {
    NET_BUFFER_LIST_STATUS(tx_net_buffer_list->net_buffer_list) =
        tx_net_buffer_list->status;
    if (*nbl == nullptr) {
      *nbl = tx_net_buffer_list->net_buffer_list;
    } else {
      NET_BUFFER_LIST_NEXT_NBL(tx_net_buffer_list->net_buffer_list) = *nbl;
      *nbl = tx_net_buffer_list->net_buffer_list;
    }

    FreeMemory(tx_net_buffer_list);
  }
}

}  // namespace

bool TxRingDma::Init(UINT32 id, UINT32 slice, UINT32 traffic_class,
                     UINT32 num_descriptor, UINT32 notify_id,
                     AdapterResources* adapter_resource,
                     AdapterStatistics* statistics,
                     const DeviceCounter* device_counters) {
  PAGED_CODE();

  NdisAllocateSpinLock(&preallocated_sg_lists_lock_);
  NdisInitializeSListHead(&preallocated_sg_lists_);

  NdisAllocateSpinLock(&net_buffer_completion_queue_lock_);
  NdisInitializeListHead(&net_buffer_completion_queue_);

  NdisAllocateSpinLock(&net_buffer_to_send_queue_lock_);
  NdisInitializeListHead(&net_buffer_to_send_queue_);

  NdisInitializeNPagedLookasideList(
      &net_buffer_work_queue_lookaside_list_, /*Allocate=*/nullptr,
      /*Free=*/nullptr,
      /*Flags=*/0, max(LOOKASIDE_MINIMUM_BLOCK_SIZE, sizeof(PendingNetBuffer)),
      kGvnicMemoryTag, /*Depth=*/0);

  if (!TxRing::Init(id, slice, traffic_class, num_descriptor,
                    /*use_raw_addressing=*/true,
                    /*queue_page_list=*/nullptr, notify_id, adapter_resource,
                    statistics, device_counters)) {
    return false;
  }

  net_buffers_ =
      AllocateMemory<NET_BUFFER*>(miniport_handle(), num_descriptor_);
  if (net_buffers_ == nullptr) {
    DEBUGP(GVNIC_ERROR,
           "[%s] ERROR: Memory allocation for net buffer array failed. "
           "Attempted to allocate %u bytes.",
           __FUNCTION__, sizeof(NET_BUFFER*) * num_descriptor_);
    return false;
  }

  // If a descriptor is comprised of multiple scatter gather elements buffered
  // into contiguous memory, a pointer to the shared memory buffer for that
  // descriptor is stored here so that it can be returned to the pool.
  consolidated_descriptor_buffers_ =
      AllocateMemory<SharedMemoryBuffer*>(miniport_handle(), num_descriptor_);
  if (consolidated_descriptor_buffers_ == nullptr) {
    DEBUGP(GVNIC_ERROR,
           "[%s] ERROR: Memory allocation for consolidated descriptor buffer "
           "array failed. Attempted to allocate %u bytes.",
           __FUNCTION__, sizeof(SharedMemoryBuffer*) * num_descriptor_);
    return false;
  }

  if (!buffer_pool_.InitializeTxBufferPool(miniport_handle(),
                                           num_descriptor_)) {
    DEBUGP(GVNIC_ERROR,
           "[%s] ERROR: Unable to initialize buffer pool. Instances with low "
           "available system memory should use QPL mode.",
           __FUNCTION__);
    return false;
  }

  if (!PreallocateSGLists(num_descriptor_ / kPreallocatedSGListFactor)) {
    // Using preallocated SG lists is optional. If we are too low on
    // non-paged memory to allocate the requested number of buffers, it's
    // better to free them all and just allocate them on demand.
    FreePreallocatedSGLists();
  }

  return true;
}

// Release is not thread safe.
void TxRingDma::Release() {
  PAGED_CODE();

  bool was_initialized = Invalidate();
  if (!was_initialized) {
    return;
  }

  CleanPendingPackets();

  FreeMemory(net_buffers_);
  FreeBufferPool();
  FreePreallocatedSGLists();

  NdisFreeSpinLock(&preallocated_sg_lists_lock_);
  NdisFreeSpinLock(&net_buffer_to_send_queue_lock_);
  NdisFreeSpinLock(&net_buffer_completion_queue_lock_);

  NdisDeleteNPagedLookasideList(&net_buffer_work_queue_lookaside_list_);

  TxRing::Release();
}

void TxRingDma::SendBufferList(PNET_BUFFER_LIST net_buffer_list,
                               bool is_dpc_level) {
  TxNetBufferList* net_packet = GetTxNetBufferList(net_buffer_list);
  if (!net_packet) {
    CompleteNetBufferListWithStatus(net_buffer_list, NDIS_STATUS_RESOURCES,
                                    is_dpc_level);
    return;
  }

  net_packet->num_net_buffer = GetNetBufferCount(*net_buffer_list);

  NET_BUFFER* net_buffer = NET_BUFFER_LIST_FIRST_NB(net_buffer_list);
  while (net_buffer != nullptr) {
    net_buffer->MiniportReserved[kNetBufferTxNetBufferListIdx] = net_packet;
    net_buffer->MiniportReserved[kNetBufferTxRingIdx] = this;

    PreallocatedSGList* preallocated_sg_list = GetPrellocatedSGListFromPool();
    net_buffer->MiniportReserved[kNetBufferPrellocatedSGList] =
        preallocated_sg_list;

    // If this is the last net buffer we might complete the net buffer list
    // before NdisMAllocateNetBufferSGList returns, which would make it no
    // longer safe to access the next net buffer field.
    NET_BUFFER* next_net_buffer = NET_BUFFER_NEXT_NB(net_buffer);

    NDIS_STATUS status;
    if (IsFailedTxNetBufferList(*net_packet)) {
      status = NDIS_STATUS_FAILURE;
    } else {
      KIRQL old_irql = 0;
      if (!is_dpc_level) {
        NT_ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);
        NDIS_RAISE_IRQL_TO_DISPATCH(&old_irql);
      }
      status = NdisMAllocateNetBufferSGList(
          /*NdisMiniportDmaHandle=*/dma_handle(),
          /*NetBuffer=*/net_buffer,
          /*Context=*/net_buffer,
          /*Flags=*/NDIS_SG_LIST_WRITE_TO_DEVICE,
          /*ScatterGatherListBuffer=*/
          preallocated_sg_list ? preallocated_sg_list->buffer : nullptr,
          /*ScatterGatherListBufferSize=*/
          preallocated_sg_list ? preallocated_sg_list->buffer_size : 0);
      if (!is_dpc_level) {
        NDIS_LOWER_IRQL(old_irql, DISPATCH_LEVEL);
      }
    }

    if (status != NDIS_STATUS_SUCCESS) {
      FailTxNetBufferList(net_packet, is_dpc_level, status);
    }

    net_buffer = next_net_buffer;
  }
}

UINT32 TxRingDma::GetNextSGIndexPastOffset(
    const SCATTER_GATHER_LIST& scatter_gather_list, UINT32 current_index,
    UINT32 offset, UINT32* offset_into_current_element) {
  NT_ASSERT(offset_into_current_element != nullptr);

  while (current_index < scatter_gather_list.NumberOfElements) {
    if (scatter_gather_list.Elements[current_index].Length <= offset) {
      // The current element's data falls completely within the offset, so
      // subtract the element's length from the offset and move on to the next
      // element.
      offset -= scatter_gather_list.Elements[current_index].Length;
      current_index++;
    } else {
      // Current element's length extends past the data offset.
      break;
    }
  }

  *offset_into_current_element = offset;
  return current_index;
}

void TxRingDma::FailTxNetBufferList(TxNetBufferList* tx_nbl, bool is_dpc_level,
                                    NDIS_STATUS error_status) {
  NT_ASSERT(tx_nbl != nullptr);
  NT_ASSERT(error_status != NDIS_STATUS_SUCCESS);

  if (!IsFailedTxNetBufferList(*tx_nbl)) {
    // Don't overwrite the first error status.
    tx_nbl->status = error_status;
  }

  if (InterlockedIncrement(&tx_nbl->num_ready_net_buffer) !=
      tx_nbl->num_net_buffer) {
    return;
  }

  // The entire net buffer list has either been processed by the HAL and
  // marshalled, or failed. The net buffer list can now be cleaned up and
  // completed.
  NET_BUFFER* net_buffer = NET_BUFFER_LIST_FIRST_NB(tx_nbl->net_buffer_list);
  while (net_buffer != nullptr) {
    NET_BUFFER* next_net_buffer = NET_BUFFER_NEXT_NB(net_buffer);
    FailProcessSGList(net_buffer, is_dpc_level, error_status);
    net_buffer = next_net_buffer;
  }
}

void TxRingDma::FailProcessSGList(NET_BUFFER* net_buffer, bool is_dpc_level,
                                  NDIS_STATUS error_status) {
  NT_ASSERT(net_buffer != nullptr);
  NT_ASSERT(error_status != NDIS_STATUS_SUCCESS);

  if (net_buffer->ScatterGatherList != nullptr) {
    KIRQL old_irql = 0;
    if (!is_dpc_level) {
      NT_ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);
      NDIS_RAISE_IRQL_TO_DISPATCH(&old_irql);
    }
    NdisMFreeNetBufferSGList(dma_handle(), net_buffer->ScatterGatherList,
                             net_buffer);
    if (!is_dpc_level) {
      NDIS_LOWER_IRQL(old_irql, DISPATCH_LEVEL);
    }
    net_buffer->ScatterGatherList = nullptr;
  }

  ReturnPreallocatedSGListToPool(net_buffer);

  TxNetBufferList* tx_net_buffer_list = static_cast<TxNetBufferList*>(
      net_buffer->MiniportReserved[kNetBufferTxNetBufferListIdx]);
  if (tx_net_buffer_list != nullptr) {
    net_buffer->MiniportReserved[kNetBufferTxNetBufferListIdx] = nullptr;
    if (!IsFailedTxNetBufferList(*tx_net_buffer_list)) {
      // Don't overwrite the first error status.
      tx_net_buffer_list->status = error_status;
    }
    ReportNetBufferSent(tx_net_buffer_list, is_dpc_level);
  }
}

void TxRingDma::PendRemainingNetBuffers(NET_BUFFER* net_buffer) {
  bool fail_remaining_buffers = false;
  while (net_buffer != nullptr) {
    NET_BUFFER* next_net_buffer = NET_BUFFER_NEXT_NB(net_buffer);
    if (!fail_remaining_buffers &&
        !AppendNetBufferToWorkQueue(net_buffer, &net_buffer_to_send_queue_,
                                    &net_buffer_to_send_queue_lock_)) {
      DEBUGP(GVNIC_ERROR,
             "[%s] ERROR: Failed to insert NET_BUFFER (%p) into work queue "
             "due to low non-paged memory. Failing remaining buffers.",
             __FUNCTION__, net_buffer);
      fail_remaining_buffers = true;
    }

    if (fail_remaining_buffers) {
      DEBUGP(GVNIC_ERROR,
             "[%s] ERROR: Failed  NET_BUFFER (%p) due to low non-paged memory.",
             __FUNCTION__, net_buffer);
      FailProcessSGList(net_buffer, /*is_dpc_level=*/true,
                        NDIS_STATUS_RESOURCES);
    } else {
      DEBUGP(GVNIC_WARNING,
             "[%s] WARNING: Had to appended NET_BUFFER (%p) to the end of "
             "the work queue.",
             __FUNCTION__, net_buffer);
    }

    net_buffer = next_net_buffer;
  }
}

void TxRingDma::ProcessSGList(NET_BUFFER* net_buffer,
                              SCATTER_GATHER_LIST* scatter_gather_list) {
  NT_ASSERT(scatter_gather_list != nullptr &&
            scatter_gather_list->NumberOfElements > 0);
  NT_ASSERT(net_buffer != nullptr);

  // Keep a pointer to the SCATTER_GATHER_LIST since we will need to free it
  // once NIC sends the packet out.
  net_buffer->ScatterGatherList = scatter_gather_list;
  auto* tx_net_buffer_list = static_cast<TxNetBufferList*>(
      net_buffer->MiniportReserved[kNetBufferTxNetBufferListIdx]);

  // We ask the HAL to provide the scatter gather list for each net buffer in
  // order, but the HAL calls back into this TxRing as soon as each SGL is
  // ready. To maintain the original net buffer order we track how many net
  // buffers have been processed, and the final net buffer being processed
  // triggers all net buffers in the net buffer list to be written to the ring.
  if (InterlockedIncrement(&tx_net_buffer_list->num_ready_net_buffer) !=
      tx_net_buffer_list->num_net_buffer) {
    return;
  }

  NET_BUFFER* net_buffer_from_list =
      NET_BUFFER_LIST_FIRST_NB(tx_net_buffer_list->net_buffer_list);
  while (net_buffer_from_list != nullptr) {
    NET_BUFFER* next_net_buffer = NET_BUFFER_NEXT_NB(net_buffer_from_list);

    NDIS_STATUS status;
    if (is_init()) {
      status = AttemptProcessSGList(net_buffer_from_list,
                                    net_buffer_from_list->ScatterGatherList);
    } else {
      status = NDIS_STATUS_RESET_IN_PROGRESS;
    }

    switch (status) {
      case NDIS_STATUS_RESOURCES:
        // If we pend one net buffer due to a lack of descriptors, we need to
        // pend the rest of the net buffers in the net buffer list to maintain
        // ordering even if they would have fit.
        PendRemainingNetBuffers(net_buffer_from_list);
        return;
      case NDIS_STATUS_SUCCESS:
        break;
      default:
        FailProcessSGList(net_buffer_from_list, /*is_dpc_level=*/true, status);
        break;
    }

    net_buffer_from_list = next_net_buffer;
  }
}

NDIS_STATUS TxRingDma::AttemptProcessSGList(
    NET_BUFFER* net_buffer, SCATTER_GATHER_LIST* scatter_gather_list) {
  NT_ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);
  NT_ASSERT(net_buffer != nullptr);

  SpinLockContext lock_context(&lock_, /*is_dpc_level=*/true);

  auto* tx_net_buffer_list = static_cast<TxNetBufferList*>(
      net_buffer->MiniportReserved[kNetBufferTxNetBufferListIdx]);
  if (IsFailedTxNetBufferList(*tx_net_buffer_list)) {
    return NDIS_STATUS_FAILURE;
  }

  // The only time a net buffer doesn't have a generated scatter gather list
  // is when the net buffer list has already been marked as failed.
  NT_ASSERT(scatter_gather_list != nullptr);

  if (GetAvailableDescriptors() == 0) {
    // We will know exactly how many descriptors we need later, but we will
    // always need a least one.
    DEBUGP(GVNIC_WARNING, "[%s] WARNING: No descriptors remaining.",
           __FUNCTION__);
    return NDIS_STATUS_RESOURCES;
  }

  // Build descriptor.
  const UINT32 desc_idx = num_request_segments_ & descriptor_mask_;
  TxNetBuffer tx_net_buffer(net_buffer, tx_net_buffer_list->checksum_info,
                            tx_net_buffer_list->lso_info, eth_header_len_);

  UINT32 pending_num_request_segments = 0;
  UINT32 first_segment_offset = 0;
  UINT32 nb_offset = NET_BUFFER_CURRENT_MDL_OFFSET(net_buffer);
  const UINT32 nb_data_length = NET_BUFFER_DATA_LENGTH(net_buffer);

  UINT32 index = GetNextSGIndexPastOffset(
      *scatter_gather_list, /*current_index=*/0, nb_offset, &nb_offset);
  if (index == scatter_gather_list->NumberOfElements) {
    // This should never happen.
    DEBUGP(GVNIC_ERROR,
           "[%s] Ran out of scatter gather entries when trying to find the "
           "start of the data section, expected %u bytes of data.",
           __FUNCTION__, nb_data_length);
    return NDIS_STATUS_FAILURE;
  }

  // For LSO packets the first scatter gather element forms the packet
  // descriptor.
  //
  // For non-LSO packets, there are three relevant cases to consider when
  // constructing the packet descriptor:
  // 1) There is only one element with data.
  // 2) The first element containing data contains more than 182 bytes.
  // 3) The first element contains less than 182 bytes but there are additional
  //    elements.
  //
  // In cases 1 and 2 we can construct the first packet descriptor directly
  // from the scatter gather element. In case 3 we must traverse the list
  // buffering bytes until we buffer 182 bytes or run out of data.
  TxPacketDescriptor* packet_desc =
      &descriptor_ring_.virtual_address()[desc_idx].package_descriptor;
  if (tx_net_buffer.is_lso() ||
      scatter_gather_list->Elements[index].Length - nb_offset >=
          kBytesRequiredInTxPacketDescriptor ||
      index == (scatter_gather_list->NumberOfElements - 1)) {
    // This is either case 1 or case 2 where the first element fully contains
    // the packet header, or the packet is using LSO.
    PacketSegmentInfo packet_segment_info = {};
    packet_segment_info.packet_length =
        scatter_gather_list->Elements[index].Length - nb_offset;
    packet_segment_info.packet_offset =
        scatter_gather_list->Elements[index].Address.QuadPart + nb_offset;
    packet_segment_info.data_segment_count = 0;
    FillTxPacketDescriptor(tx_net_buffer, packet_segment_info, packet_desc);

    pending_num_request_segments++;
    index++;
  } else {
    // This is case 3 where the header might be fragmented across multiple
    // elements.
    DEBUGP(GVNIC_VERBOSE,
           "[%s] Buffering the first %u bytes of the scatter gather list.",
           __FUNCTION__,
           min(nb_data_length, kBytesRequiredInTxPacketDescriptor));

    NT_ASSERT(consolidated_descriptor_buffers_[desc_idx] == nullptr);
    consolidated_descriptor_buffers_[desc_idx] =
        buffer_pool_.GetBufferFromPool(kBytesRequiredInTxPacketDescriptor);
    if (consolidated_descriptor_buffers_[desc_idx] == nullptr) {
      DEBUGP(GVNIC_WARNING,
             "[%s] WARNING: Unable to acquire a %u byte buffer to ensure the "
             "packet header is contiguous.",
             __FUNCTION__, kBytesRequiredInTxPacketDescriptor);
      return NDIS_STATUS_RESOURCES;
    }

    SharedMemory<UCHAR>* shared_memory =
        &(consolidated_descriptor_buffers_[desc_idx]->shared_memory);

    // Iterate through the scatter gather list past the data that will be
    // buffered. Remaining data will be copied into segment descriptors.
    if (nb_data_length <= kBytesRequiredInTxPacketDescriptor) {
      // We will defragment the entire SGL into the buffer, so there will be no
      // segment descriptors.
      index = scatter_gather_list->NumberOfElements;
    } else {
      index = GetNextSGIndexPastOffset(
          *scatter_gather_list, index,
          nb_offset + kBytesRequiredInTxPacketDescriptor,
          &first_segment_offset);
    }

    // Iterate through the MDL chain to copy the memory containing the header
    // into a buffer.
    const UINT32 bytes_to_buffer =
        min(nb_data_length, kBytesRequiredInTxPacketDescriptor);
    if (!CopyDataFromMdlChainToBuffer(NET_BUFFER_CURRENT_MDL(net_buffer),
                                      NET_BUFFER_CURRENT_MDL_OFFSET(net_buffer),
                                      bytes_to_buffer, shared_memory)) {
      ReturnBufferToPool(desc_idx);
      return NDIS_STATUS_FAILURE;
    }

    PacketSegmentInfo packet_segment_info = {};
    packet_segment_info.packet_length = bytes_to_buffer;
    packet_segment_info.packet_offset =
        shared_memory->physical_address().QuadPart;
    packet_segment_info.data_segment_count = 0;
    FillTxPacketDescriptor(tx_net_buffer, packet_segment_info, packet_desc);

    pending_num_request_segments++;
  }

  const UINT32 descriptors_required_for_segments =
      scatter_gather_list->NumberOfElements - index;
  const UINT32 descriptors_available_for_segments =
      min(GetAvailableDescriptors(), kMaxDescriptorsPerPacket) - 1;

  if (descriptors_required_for_segments > descriptors_available_for_segments) {
    if (descriptors_available_for_segments == 0) {
      DEBUGP(GVNIC_WARNING,
             "[%s] WARNING: No descriptors available for segments.",
             __FUNCTION__);
      ReturnBufferToPool(desc_idx);
      return NDIS_STATUS_RESOURCES;
    }

    // If there's only one descriptor to consolidate all segments into, we may
    // have an offset into the first element being consolidated as some of this
    // element might have already been buffered.
    UINT32 first_consolidated_element_offset =
        descriptors_available_for_segments == 1 ? first_segment_offset : 0;

    // Attempt to consolidate the elements we don't have descriptors for.
    const UINT32 bytes_without_descriptors =
        CountBytesInSGElements(index + descriptors_available_for_segments - 1,
                               scatter_gather_list->NumberOfElements,
                               *scatter_gather_list) -
        first_consolidated_element_offset;

    SharedMemoryBuffer* consolidated_desc_buffer =
        buffer_pool_.GetBufferFromPool(bytes_without_descriptors);
    if (consolidated_desc_buffer == nullptr) {
      DEBUGP(GVNIC_WARNING,
             "[%s] WARNING: Needed %u descriptors, but have %u available. "
             "Unable to acquire a buffer large enough to consolidate remaining "
             "segments of size %u bytes.",
             __FUNCTION__, descriptors_required_for_segments,
             descriptors_available_for_segments, bytes_without_descriptors);
      ReturnBufferToPool(desc_idx);
      return NDIS_STATUS_RESOURCES;
    }

    // Save a final descriptor for the consolidated descriptors.
    UINT32 final_index_to_copy = index + descriptors_available_for_segments - 1;
    WriteSegmentDescriptorsFromSGList(
        *scatter_gather_list, index, final_index_to_copy, first_segment_offset,
        tx_net_buffer, packet_desc, &pending_num_request_segments);

    const UINT32 consolidated_tail_desc_idx =
        (num_request_segments_ + pending_num_request_segments) &
        descriptor_mask_;

    NT_ASSERT(consolidated_descriptor_buffers_[consolidated_tail_desc_idx] ==
              nullptr);
    consolidated_descriptor_buffers_[consolidated_tail_desc_idx] =
        consolidated_desc_buffer;
    SharedMemory<UCHAR>* shared_memory =
        &consolidated_desc_buffer->shared_memory;

    if (!CopyTailDataFromMdlChainToBuffer(net_buffer, bytes_without_descriptors,
                                          shared_memory)) {
      ReturnBufferToPool(desc_idx);
      ReturnBufferToPool(consolidated_tail_desc_idx);
      return NDIS_STATUS_FAILURE;
    }

    // Write the consolidated segment descriptor. This descriptor points to a
    // buffer which contains every segment we didn't have a descriptor for.
    WriteSegmentDescriptor(
        bytes_without_descriptors, shared_memory->physical_address().QuadPart,
        tx_net_buffer, packet_desc, &pending_num_request_segments);
  } else {
    // Copy all remaining scatter gather elements into segment descriptors.
    WriteSegmentDescriptorsFromSGList(
        *scatter_gather_list, index, scatter_gather_list->NumberOfElements,
        first_segment_offset, tx_net_buffer, packet_desc,
        &pending_num_request_segments);
  }

  const UINT32 last_desc_idx =
      (num_request_segments_ + pending_num_request_segments - 1) &
      descriptor_mask_;
  NT_ASSERT(net_buffers_[last_desc_idx] == nullptr);
  net_buffers_[last_desc_idx] = net_buffer;

  // Update statistics.
  statistics()->AddSentPacket(tx_net_buffer.data_length(),
                              tx_net_buffer.eth_header());

  NT_ASSERT(packet_desc->descriptor_count == pending_num_request_segments);
  num_request_segments_ += pending_num_request_segments;
  WriteDoorbell(num_request_segments_);

  DEBUGP(GVNIC_VERBOSE, "[%s] TxRing id - %u: requested - %u, done - %u",
         __FUNCTION__, id(), num_request_segments_, num_sent_segments_);

  return NDIS_STATUS_SUCCESS;
}

void TxRingDma::WriteSegmentDescriptorsFromSGList(
    const SCATTER_GATHER_LIST& scatter_gather_list, UINT32 index_from,
    UINT32 index_to, UINT32 first_segment_offset,
    const TxNetBuffer& tx_net_buffer, TxPacketDescriptor* packet_desc,
    UINT32* pending_num_request_segments) {
  for (UINT32 index = index_from, offset = first_segment_offset;
       index < index_to; index++, offset = 0) {
    const UINT64 segment_address =
        scatter_gather_list.Elements[index].Address.QuadPart;
    const UINT32 segment_length = scatter_gather_list.Elements[index].Length;

    WriteSegmentDescriptor(segment_length - offset, segment_address + offset,
                           tx_net_buffer, packet_desc,
                           pending_num_request_segments);
  }
}

void TxRingDma::WriteSegmentDescriptor(UINT32 length, UINT64 address,
                                       const TxNetBuffer& tx_net_buffer,
                                       TxPacketDescriptor* packet_desc,
                                       UINT32* pending_num_request_segments) {
  UINT32 seg_desc_idx =
      (num_request_segments_ + *pending_num_request_segments) &
      descriptor_mask_;

  TxSegmentDescriptor* seg_desc =
      &descriptor_ring_.virtual_address()[seg_desc_idx].segment_descriptor;
  FillTxSegmentDescriptor(address, length, tx_net_buffer, seg_desc);

  packet_desc->descriptor_count++;
  (*pending_num_request_segments)++;
}

void TxRingDma::ReportNetBufferSent(TxNetBufferList* tx_net_buffer_list,
                                    bool is_dpc_level) {
  // Check if all NET_BUFFER is sent. If so, report the completion of the send
  // request.
  if (InterlockedIncrement(&tx_net_buffer_list->num_sent_net_buffer) ==
      tx_net_buffer_list->num_net_buffer) {
    CompleteNetBufferListWithStatus(tx_net_buffer_list->net_buffer_list,
                                    tx_net_buffer_list->status, is_dpc_level);
    FreeMemory(tx_net_buffer_list);
  }
}

void TxRingDma::ProcessCompletePackets() {
  NT_ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);
  NET_BUFFER* net_buffer_to_pend = nullptr;

  {
    SpinLockContext lock_context(&lock_, true);
    const UINT32 packets_sent = ReadPacketsSent();
    while (packets_sent != num_sent_segments_) {
      UINT32 segment_idx = num_sent_segments_ & descriptor_mask_;
      ReturnBufferToPool(segment_idx);
      net_buffer_to_pend = net_buffers_[segment_idx];
      if (net_buffer_to_pend != nullptr) {
        net_buffers_[segment_idx] = nullptr;
        if (!AppendNetBufferToWorkQueue(net_buffer_to_pend,
                                        &net_buffer_completion_queue_,
                                        &net_buffer_completion_queue_lock_)) {
          // If we can't allocate enough memory to pend this net buffer,
          // we stop pending net buffers and start completing what we have
          // already pended. This is very unlikely given the small size of
          // the memory allocations.
          num_sent_segments_++;
          break;
        }
        net_buffer_to_pend = nullptr;
      }
      num_sent_segments_++;
    }
  }

  // The descriptor ring now has free slots for net buffers we have previously
  // pended.
  SchedulePendingNetBuffers();

  // Take and complete net buffers from the completion queue. This is thread
  // safe, and a spinlock should not be held during these framework calls.
  NET_BUFFER* net_buffer_to_complete =
      net_buffer_to_pend
          ? net_buffer_to_pend
          : PopNetBufferFromWorkQueue(&net_buffer_completion_queue_,
                                      &net_buffer_completion_queue_lock_);
  PNET_BUFFER_LIST net_buffer_list = nullptr;
  while (net_buffer_to_complete != nullptr) {
    NdisMFreeNetBufferSGList(dma_handle(),
                             net_buffer_to_complete->ScatterGatherList,
                             net_buffer_to_complete);
    net_buffer_to_complete->ScatterGatherList = nullptr;
    ReturnPreallocatedSGListToPool(net_buffer_to_complete);

    auto* tx_net_buffer_list = static_cast<TxNetBufferList*>(
        net_buffer_to_complete->MiniportReserved[kNetBufferTxNetBufferListIdx]);
    ReportNetBufferSentWithoutCompletion(tx_net_buffer_list, &net_buffer_list);

    net_buffer_to_complete = PopNetBufferFromWorkQueue(
        &net_buffer_completion_queue_, &net_buffer_completion_queue_lock_);
  }
  if (net_buffer_list != nullptr) {
    NdisMSendNetBufferListsComplete(miniport_handle(), net_buffer_list,
                                    NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL);
  }

  DEBUGP(GVNIC_VERBOSE, "[%s] TxRing id - %u: requested - %u, done - %u",
         __FUNCTION__, id(), num_request_segments_, num_sent_segments_);
}

void TxRingDma::ReturnBufferToPool(UINT32 desc) {
  if (consolidated_descriptor_buffers_[desc] != nullptr) {
    buffer_pool_.ReturnBufferToPool(consolidated_descriptor_buffers_[desc]);
    consolidated_descriptor_buffers_[desc] = nullptr;
  }
}

void TxRingDma::FreeBufferPool() {
  if (consolidated_descriptor_buffers_ != nullptr) {
    for (UINT32 i = 0; i < num_descriptor_; i++) {
      ReturnBufferToPool(i);
    }
    FreeMemory(consolidated_descriptor_buffers_);
    consolidated_descriptor_buffers_ = nullptr;
  }

  buffer_pool_.Release();
}

void TxRingDma::CleanPendingPackets() {
  NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

  // Fail NET_BUFFERs in the descriptor ring.
  UINT32 processed_segments = num_sent_segments_;
  while (num_request_segments_ != processed_segments) {
    UINT32 segment_idx = processed_segments & descriptor_mask_;
    NET_BUFFER* net_buffer_to_free = net_buffers_[segment_idx];
    if (net_buffer_to_free != nullptr) {
      net_buffers_[segment_idx] = nullptr;
      FailProcessSGList(net_buffer_to_free, /*is_dpc_level=*/false,
                        NDIS_STATUS_RESET_IN_PROGRESS);
    }
    processed_segments++;
  }

  // Fail NET_BUFFERs previously pended due to low descriptors.
  NET_BUFFER* net_buffer = PopNetBufferFromWorkQueue(
      &net_buffer_to_send_queue_, &net_buffer_to_send_queue_lock_);
  while (net_buffer) {
    FailProcessSGList(net_buffer, /*is_dpc_level=*/false,
                      NDIS_STATUS_RESET_IN_PROGRESS);
    net_buffer = PopNetBufferFromWorkQueue(&net_buffer_to_send_queue_,
                                           &net_buffer_to_send_queue_lock_);
  }
}

void TxRingDma::SchedulePendingNetBuffers() {
  NDIS_STATUS status = NDIS_STATUS_SUCCESS;
  NET_BUFFER* net_buffer = PopNetBufferFromWorkQueue(
      &net_buffer_to_send_queue_, &net_buffer_to_send_queue_lock_);

  while (net_buffer != nullptr) {
    status = AttemptProcessSGList(net_buffer, net_buffer->ScatterGatherList);
    if (status != NDIS_STATUS_SUCCESS) {
      break;
    }

    net_buffer = PopNetBufferFromWorkQueue(&net_buffer_to_send_queue_,
                                           &net_buffer_to_send_queue_lock_);
  }

  switch (status) {
    case NDIS_STATUS_RESOURCES:
      // The TxRing didn't have the resources to process this net buffer, so
      // it's inserted at the beginning of the work queue to be handled first
      // when resources are next available.
      if (PrependNetBufferToWorkQueue(net_buffer, &net_buffer_to_send_queue_,
                                      &net_buffer_to_send_queue_lock_)) {
        break;
      }
      DEBUGP(GVNIC_ERROR,
             "[%s] ERROR: Failed to insert NET_BUFFER (%p) back into work "
             "queue due to low non-paged memory.",
             __FUNCTION__, net_buffer);
      __fallthrough;
    default:
      FailProcessSGList(net_buffer, /*is_dpc_level=*/true, status);
      break;
    case NDIS_STATUS_SUCCESS:
      break;
  }
}

bool TxRingDma::PreallocateSGLists(UINT32 num_lists) {
  const UINT32 buffer_size = recommended_sg_list_size();
  if (buffer_size == 0) {
    DEBUGP(GVNIC_WARNING, "[%s] Recommended SG list size is 0 bytes.",
           __FUNCTION__);
    return false;
  } else {
    DEBUGP(GVNIC_INFO, "[%s] Recommended SG list size is %u bytes.",
           __FUNCTION__, buffer_size);
  }

  for (UINT32 i = 0; i < num_lists; i++) {
    PreallocatedSGList* entry =
        AllocateMemory<PreallocatedSGList>(miniport_handle());
    if (entry != nullptr) {
      entry->buffer = NdisAllocateMemoryWithTagPriority(
          miniport_handle(), buffer_size, kGvnicMemoryTag, NormalPoolPriority);
    }

    if (entry == nullptr || entry->buffer == nullptr) {
      DEBUGP(GVNIC_WARNING,
             "[%s] Failed to preallocate %u of %u SG lists of size %u.",
             __FUNCTION__, num_lists - i, num_lists,
             sizeof(PreallocatedSGList) + buffer_size);
      FreeMemory(entry);
      return false;
    }

    entry->list_entry.Next = nullptr;
    entry->buffer_size = buffer_size;

    NdisInterlockedPushEntrySList(&preallocated_sg_lists_, &entry->list_entry,
                                  &preallocated_sg_lists_lock_);
  }

  return true;
}

void TxRingDma::FreePreallocatedSGLists() {
  SLIST_ENTRY* entry = NdisInterlockedPopEntrySList(
      &preallocated_sg_lists_, &preallocated_sg_lists_lock_);
  while (entry != nullptr) {
    PreallocatedSGList* sg_list =
        CONTAINING_RECORD(entry, PreallocatedSGList, list_entry);

    FreeMemory(sg_list->buffer);
    FreeMemory(sg_list);

    entry = NdisInterlockedPopEntrySList(&preallocated_sg_lists_,
                                         &preallocated_sg_lists_lock_);
  }
}

PreallocatedSGList* TxRingDma::GetPrellocatedSGListFromPool() {
  SLIST_ENTRY* sg_list = NdisInterlockedPopEntrySList(
      &preallocated_sg_lists_, &preallocated_sg_lists_lock_);

  return sg_list ? CONTAINING_RECORD(sg_list, PreallocatedSGList, list_entry)
                 : nullptr;
}

void TxRingDma::ReturnPreallocatedSGListToPool(NET_BUFFER* net_buffer) {
  NT_ASSERT(net_buffer != nullptr);
  if (net_buffer->MiniportReserved[kNetBufferPrellocatedSGList] != nullptr) {
    PreallocatedSGList* preallocated_sg_list =
        reinterpret_cast<PreallocatedSGList*>(
            net_buffer->MiniportReserved[kNetBufferPrellocatedSGList]);
    net_buffer->MiniportReserved[kNetBufferPrellocatedSGList] = nullptr;

    NdisInterlockedPushEntrySList(&preallocated_sg_lists_,
                                  &preallocated_sg_list->list_entry,
                                  &preallocated_sg_lists_lock_);
  }
}

bool TxRingDma::AppendNetBufferToWorkQueue(NET_BUFFER* net_buffer,
                                           PLIST_ENTRY work_queue,
                                           PNDIS_SPIN_LOCK work_queue_lock) {
  PendingNetBuffer* pending_net_buffer =
      static_cast<PendingNetBuffer*>(NdisAllocateFromNPagedLookasideList(
          &net_buffer_work_queue_lookaside_list_));
  if (pending_net_buffer == nullptr) {
    return false;
  }

  pending_net_buffer->net_buffer = net_buffer;
  NdisInterlockedInsertTailList(work_queue, &pending_net_buffer->list_entry,
                                work_queue_lock);

  return true;
}

bool TxRingDma::PrependNetBufferToWorkQueue(NET_BUFFER* net_buffer,
                                            PLIST_ENTRY work_queue,
                                            PNDIS_SPIN_LOCK work_queue_lock) {
  PendingNetBuffer* pending_net_buffer =
      static_cast<PendingNetBuffer*>(NdisAllocateFromNPagedLookasideList(
          &net_buffer_work_queue_lookaside_list_));
  if (pending_net_buffer == nullptr) {
    return false;
  }

  pending_net_buffer->net_buffer = net_buffer;
  NdisInterlockedInsertHeadList(work_queue, &pending_net_buffer->list_entry,
                                work_queue_lock);

  return true;
}

NET_BUFFER* TxRingDma::PopNetBufferFromWorkQueue(
    PLIST_ENTRY work_queue, PNDIS_SPIN_LOCK work_queue_lock) {
  LIST_ENTRY* entry =
      NdisInterlockedRemoveHeadList(work_queue, work_queue_lock);
  if (entry == nullptr) {
    return nullptr;
  }

  PendingNetBuffer* pending_net_buffer =
      CONTAINING_RECORD(entry, PendingNetBuffer, list_entry);
  NET_BUFFER* net_buffer = pending_net_buffer->net_buffer;

  NdisFreeToNPagedLookasideList(&net_buffer_work_queue_lookaside_list_,
                                pending_net_buffer);

  return net_buffer;
}

bool TxBufferPool::InitializeTxBufferPool(NDIS_HANDLE miniport_handle,
                                          UINT32 num_descriptors) {
  NT_ASSERT(!IsInitialized());

  NdisAllocateSpinLock(&buffer_pool_spin_lock_);

  NdisInitializeSListHead(&small_buffers_);
  NdisInitializeSListHead(&medium_buffers_);
  NdisInitializeSListHead(&large_buffers_);
  NdisInitializeSListHead(&enormous_buffers_);

  UINT32 num_small_buffers = max(num_descriptors / kSmallBufferFactor, 1);
  if (!AllocateBuffers(miniport_handle, num_small_buffers,
                       kSmallBufferSizeBytes, &small_buffers_)) {
    DEBUGP(GVNIC_ERROR,
           "[%s] Failed to allocate small buffers which are required for "
           "TxRings using raw addressing.",
           __FUNCTION__);
    FreeTxBufferPool();
    return false;
  }

  // Since we don't fail net buffers for lack of resources, we need at least one
  // buffer capable of consolidating any scatter gather list to prevent a tail
  // heavy net buffer from stalling the descriptor ring.
  if (!AllocateBuffers(miniport_handle, /*count=*/1, kEnormousBufferSizeBytes,
                       &enormous_buffers_)) {
    DEBUGP(GVNIC_ERROR,
           "[%s] Failed to allocate a single enormous buffer which is "
           "required for TxRings using raw addressing.",
           __FUNCTION__);
    FreeTxBufferPool();
    return false;
  }

  // These buffers are optional, and won't be allocated if the system is low on
  // shared memory.
  bool low_memory = false;
  UINT32 num_medium_buffers = max(num_descriptors / kMediumBufferFactor, 1);
  if (!AllocateBuffers(miniport_handle, num_medium_buffers,
                       kMediumBufferSizeBytes, &medium_buffers_)) {
    low_memory = true;
    EnableLowMemoryMode();
  }

  UINT32 num_large_buffers = max(num_descriptors / kLargeBufferFactor, 1);
  if (!low_memory && !AllocateBuffers(miniport_handle, num_large_buffers,
                                      kLargeBufferSizeBytes, &large_buffers_)) {
    low_memory = true;
    EnableLowMemoryMode();
  }

  if (low_memory) {
    DEBUGP(GVNIC_WARNING,
           "[%s] The system is low on available shared memory, so optional "
           "buffers have been freed.",
           __FUNCTION__);
  }

  InterlockedExchange(&is_init_, 1);
  return true;
}

bool TxBufferPool::AllocateBuffers(NDIS_HANDLE miniport_handle, UINT32 count,
                                   UINT32 size, SLIST_HEADER* pool) {
  for (UINT32 i = 0; i < count; i++) {
    SharedMemoryBuffer* entry =
        AllocateMemory<SharedMemoryBuffer>(miniport_handle);
    if (entry != nullptr) {
      entry->shared_memory.Allocate(miniport_handle, size);
    }

    if (entry == nullptr || !entry->shared_memory) {
      DEBUGP(
          GVNIC_ERROR,
          "[%s] Failed to allocate %u of %u shared memory buffers of size %u.",
          __FUNCTION__, count - i, count, size);
      FreeMemory(entry);
      return false;
    }

    entry->list_entry.Next = nullptr;
    entry->buffer_size = size;

    NdisInterlockedPushEntrySList(pool, &entry->list_entry,
                                  &buffer_pool_spin_lock_);
  }

  return true;
}

void TxBufferPool::Release() {
  bool was_initialized = Invalidate();
  if (!was_initialized) {
    return;
  }

  FreeTxBufferPool();
}

void TxBufferPool::FreeBufferPool(SLIST_HEADER* pool) {
  SLIST_ENTRY* entry =
      NdisInterlockedPopEntrySList(pool, &buffer_pool_spin_lock_);
  while (entry != nullptr) {
    SharedMemoryBuffer* buffer =
        CONTAINING_RECORD(entry, SharedMemoryBuffer, list_entry);

    buffer->shared_memory.Release();
    FreeMemory(buffer);

    entry = NdisInterlockedPopEntrySList(pool, &buffer_pool_spin_lock_);
  }
}

void TxBufferPool::EnableLowMemoryMode() {
  FreeBufferPool(&medium_buffers_);
  FreeBufferPool(&large_buffers_);
}

void TxBufferPool::FreeTxBufferPool() {
  FreeBufferPool(&small_buffers_);
  FreeBufferPool(&medium_buffers_);
  FreeBufferPool(&large_buffers_);
  FreeBufferPool(&enormous_buffers_);

  NdisFreeSpinLock(&buffer_pool_spin_lock_);
}

SharedMemoryBuffer* TxBufferPool::GetBufferFromPool(UINT32 min_buffer_size) {
  NT_ASSERT(IsInitialized());
  SLIST_ENTRY* entry = nullptr;

  if (min_buffer_size <= kSmallBufferSizeBytes) {
    entry =
        NdisInterlockedPopEntrySList(&small_buffers_, &buffer_pool_spin_lock_);
  }

  if (entry == nullptr && min_buffer_size <= kMediumBufferSizeBytes) {
    entry =
        NdisInterlockedPopEntrySList(&medium_buffers_, &buffer_pool_spin_lock_);
  }

  if (entry == nullptr && min_buffer_size <= kLargeBufferSizeBytes) {
    entry =
        NdisInterlockedPopEntrySList(&large_buffers_, &buffer_pool_spin_lock_);
  }

  if (entry == nullptr && min_buffer_size <= kEnormousBufferSizeBytes) {
    entry = NdisInterlockedPopEntrySList(&enormous_buffers_,
                                         &buffer_pool_spin_lock_);
  }

  return entry ? CONTAINING_RECORD(entry, SharedMemoryBuffer, list_entry)
               : nullptr;
}

void TxBufferPool::ReturnBufferToPool(SharedMemoryBuffer* buffer_entry) {
  NT_ASSERT(IsInitialized());
  NT_ASSERT(buffer_entry != nullptr);

  SLIST_HEADER* pool = nullptr;
  switch (buffer_entry->buffer_size) {
    case kSmallBufferSizeBytes:
      pool = &small_buffers_;
      break;
    case kMediumBufferSizeBytes:
      pool = &medium_buffers_;
      break;
    case kLargeBufferSizeBytes:
      pool = &large_buffers_;
      break;
    case kEnormousBufferSizeBytes:
      pool = &enormous_buffers_;
      break;
    default:
      // This should never happen.
      NT_ASSERT(false);
  }

  if (pool != nullptr) {
    NdisInterlockedPushEntrySList(pool, &buffer_entry->list_entry,
                                  &buffer_pool_spin_lock_);
  }
}
