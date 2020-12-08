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

#ifndef UTILS_H_
#define UTILS_H_

#include <ndis.h>  // NOLINT: include directory

// Offsets into the NET_BUFFER_LIST->MniportReserved pointer array.
enum NetBufferListMiniportReservedIndices {
  // Used to map a NetBufferList to its RxRingEntry.
  kNetBufferListRxRingEntryPtrIdx = 0,
  kBeyondMaxNetBufferListMiniportReservedIndex_DO_NOT_USE = 2,
};

// Offsets into the NET_BUFFER->MiniportReserved pointer array.
enum NetBufferMiniportReservedIndices {
  // Used to map a NetBuffer to its TxNetBufferList.
  kNetBufferTxNetBufferListIdx = 0,
  // Used to map a NetBuffer to its TxRing.
  kNetBufferTxRingIdx = 1,
  // A handle to the preallocated SG list used in a DMA operation. This should
  // only be used to return the preallocated SG list to the pool, as it might
  // not actually contain the actual SG list if it was too small.
  kNetBufferPrellocatedSGList = 2,
  kBeyondMaxNetBufferMiniportReservedIndex_DO_NOT_USE = 4,
};

// Tag used for memory allocation.
// Per NDIS doc, it is defined as a string, delimited by single quotation marks,
// with up to four characters, specified in reversed order. Function consume it
// as ULONG type.
constexpr ULONG kGvnicMemoryTag = 'mNVG';  // Gvnic Memory.

// Returns a pointer for a given offset in bytes from a given base address.
inline void* OffsetToPointer(void* base, ULONG_PTR offset) {
  return reinterpret_cast<char*>(base) + offset;
}

inline ULONG GetSystemProcessorCount() {
  ULONG processors;

#if NDIS_SUPPORT_NDIS620
  processors = NdisGroupActiveProcessorCount(ALL_PROCESSOR_GROUPS);
#else
  processors = NdisSystemProcessorCount();
#endif

  return processors;
}

// Allocate contiguous memory for sizeof(T) * count bytes and zero the
// allocated memory. If allocating memory for a C++ class, this does not call
// the constructor. If the constructor is needed use a placement new on the
// returned memory.
//
// Returns nullptr if allocation failed.
template <typename T>
inline T* AllocateMemory(NDIS_HANDLE miniport_handle, UINT count = 1) {
  UINT length = count * sizeof(T);
  void* allocatd_memory = NdisAllocateMemoryWithTagPriority(
      miniport_handle, length, kGvnicMemoryTag, NormalPoolPriority);

  if (allocatd_memory == nullptr) {
    return nullptr;
  }

  NdisZeroMemory(allocatd_memory, length);
  return reinterpret_cast<T*>(allocatd_memory);
}

// Free Memory allocated by AllocateMemory. Will check virtual_addr is validate
// before calling NdisFreeMemory.
inline void FreeMemory(void* virtual_addr) {
  if (virtual_addr) {
    // For memory allocated with NdisAllocateMemoryWithTagPriority, always set
    // Length and Memory to 0.
    NdisFreeMemory(virtual_addr, /*Length=*/0, /*MemoryFlags=*/0);
  }
}

// Return the number of bytes the address need to move forward to align
// with the cacheline_size.
inline UINT GetCacheAlignOffset(LONGLONG addr, int cacheline_size) {
  UINT offset = addr % cacheline_size;
  return offset == 0 ? 0 : (cacheline_size - offset);
}

// Return the current processor index.
inline ULONG GetCurrentProcessorIndex() {
  PROCESSOR_NUMBER proc_num;
  KeGetCurrentProcessorNumberEx(&proc_num);
  return KeGetProcessorIndexFromNumber(&proc_num);
}

// Return true if list_entry has been initialized.
inline bool IsListInitialized(const LIST_ENTRY& list_entry) {
  return (list_entry.Blink != nullptr && list_entry.Flink != nullptr);
}

#if NDIS_SUPPORT_NDIS620
// Set the GroupAffinity based on processor index.
// Return true if succeed and false if proc_index is not valid.
inline bool SetGroupAffinityFromIndex(GROUP_AFFINITY* affinity,
                                      int proc_index) {
  PROCESSOR_NUMBER proc_num;
  NDIS_STATUS status = KeGetProcessorNumberFromIndex(proc_index, &proc_num);
  if (status != NDIS_STATUS_SUCCESS) {
    return false;
  }

  affinity->Group = proc_num.Group;
  // Assign to 1 and then do bit shift to avoid compiler warnings about shifting
  // 32 bit for 64 bit integer.
  affinity->Mask = 1;
  affinity->Mask <<= proc_num.Number;
  return true;
}
#endif

// Release MDL from receive net_buffer_list.
// It is required to have one NET_BUFFER in the net_buffert_list.
inline void FreeMdlsFromReceiveNetBuffer(NET_BUFFER* net_buffer) {
  MDL* current_mdl = NET_BUFFER_FIRST_MDL(net_buffer);
  while (current_mdl != nullptr) {
    MDL* next_mdl = current_mdl->Next;
    NdisFreeMdl(current_mdl);
    current_mdl = next_mdl;
  }
  NET_BUFFER_FIRST_MDL(net_buffer) = nullptr;
  NET_BUFFER_CURRENT_MDL(net_buffer) = nullptr;
}

#endif  // UTILS_H_
