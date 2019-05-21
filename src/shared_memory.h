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

#ifndef SHARED_MEMORY_H_
#define SHARED_MEMORY_H_

#include <ndis.h>

#include "trace.h"  // NOLINT: include directory

#include "shared_memory.tmh"  // NOLINT: include directory

// Class for allocation and deallocation of one region of memory shared between
// device and driver.
//
// Caller initialize object instance. Call Allocate() to allocate a block of
// memory which is accessible for both device using PhysicalAddr() and caller
// using VirtualAddr(). Allocated memory will be released with destructor or
// call Release() explicitly.
//
// To re-allocated another block of shared memory, caller needs to call
// Release() first or Allocate() will return failure.
template <typename T>
class SharedMemory final {
 public:
  SharedMemory()
      : miniport_handle_(nullptr), buffer_virtual_address_(nullptr) {}

  // Destructor will free allocated memory.
  ~SharedMemory();

  // Not copyable or movable
  SharedMemory(const SharedMemory&) = delete;
  SharedMemory& operator=(const SharedMemory&) = delete;

  // Allocate shared memory with size count*sizeof(T).
  // Return true if succeed and false otherwise.
  // Function will return false if pre-allocated memory exist.
  //
  // It may make more sense to have a factory method and return SharedMemory as
  // a result, but it will require caller to free the memory once it is done
  // which is dangerous in the long run. To make memory management simpler,
  // caller create the instance and call Allocate() to initialize the shared
  // memory.
  bool Allocate(const NDIS_HANDLE driver_handle, ULONG count = 1);

  // Release the allocated memory.
  void Release();

  T* virtual_address() const { return buffer_virtual_address_; }
  NDIS_PHYSICAL_ADDRESS physical_address() const {
    return buffer_physical_address_;
  }

 private:
  NDIS_HANDLE miniport_handle_;
  ULONG count_;
  T* buffer_virtual_address_;
  NDIS_PHYSICAL_ADDRESS buffer_physical_address_;
};

template <typename T>
inline SharedMemory<T>::~SharedMemory() {
  PAGED_CODE();

  Release();
}

template <typename T>
inline bool SharedMemory<T>::Allocate(NDIS_HANDLE miniport_handle,
                                      ULONG count = 1) {
  PAGED_CODE();

  if (buffer_virtual_address_ != nullptr) {
    return false;
  }

  count_ = count;
  miniport_handle_ = miniport_handle;
  PVOID virtual_addr = nullptr;
  size_t length = count_ * sizeof(T);

  NdisMAllocateSharedMemory(miniport_handle_, static_cast<ULONG>(length),
                            /*cached=*/TRUE, &virtual_addr,
                            &buffer_physical_address_);
  NdisZeroMemory(virtual_addr, length);

  buffer_virtual_address_ = reinterpret_cast<T*>(virtual_addr);

  bool is_allocation_succeed = buffer_virtual_address_ != nullptr;
  DEBUGP(GVNIC_INFO, "[%s] Allocate shared memory with size %#llX return %d",
         __FUNCTION__, length, is_allocation_succeed);

  return is_allocation_succeed;
}

template <typename T>
inline void SharedMemory<T>::Release() {
  PAGED_CODE();

  if (buffer_virtual_address_ != nullptr) {
    DEBUGP(GVNIC_INFO, "[%s] Deallocate shared memory with size %#X.",
           __FUNCTION__, count_ * sizeof(T));
    NdisMFreeSharedMemory(miniport_handle_, count_ * sizeof(T), /*cached=*/TRUE,
                          buffer_virtual_address_, buffer_physical_address_);
    buffer_virtual_address_ = nullptr;
  }
}

#endif  // SHARED_MEMORY_H_
