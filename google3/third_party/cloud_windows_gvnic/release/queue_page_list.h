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

#ifndef QUEUE_PAGE_LIST_H_
#define QUEUE_PAGE_LIST_H_

#include <ndis.h>

#include "shared_memory.h"  // NOLINT: include directory

class QueuePageList final {
 public:
  QueuePageList() : page_physical_addrsess_(nullptr), pages_(nullptr) {}
  ~QueuePageList();

  // Not copyable or movable
  QueuePageList(const QueuePageList&) = delete;
  QueuePageList& operator=(const QueuePageList&) = delete;

  // Initialize the object and allocate required resources
  // Return true if allocation succeeds or false otherwise.
  bool Init(UINT32 id, UINT32 number_of_pages, NDIS_HANDLE minport_handle);

  // Release allocated pages.
  // Safe to call even if Init is not invoked yet.
  void Release();

  UINT32 id() const { return id_; }
  UINT32 num_pages() const { return num_pages_; }
  PHYSICAL_ADDRESS* page_physical_address() const {
    return page_physical_addrsess_;
  }
  PVOID* pages() const { return pages_; }

 private:
  UINT32 id_;
  UINT32 num_pages_;

  PHYSICAL_ADDRESS* page_physical_addrsess_;
  // Page virtual address.
  PVOID* pages_;

  NDIS_HANDLE miniport_handle_;
};

#endif  // QUEUE_PAGE_LIST_H_
