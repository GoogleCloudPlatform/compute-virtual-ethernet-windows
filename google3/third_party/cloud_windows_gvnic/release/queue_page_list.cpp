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

#include <ndis.h>

#include "queue_page_list.h"  // NOLINT: include directory
#include "trace.h"            // NOLINT: include directory
#include "utils.h"            // NOLINT: include directory

#include "queue_page_list.tmh"  // NOLINT: trace message header

QueuePageList::~QueuePageList() {
  PAGED_CODE();
  Release();
}

bool QueuePageList::Init(UINT32 id, UINT32 number_of_pages,
                         NDIS_HANDLE miniport_handle) {
  PAGED_CODE();

  id_ = id;
  num_pages_ = number_of_pages;
  miniport_handle_ = miniport_handle;

  DEBUGP(GVNIC_INFO, "[%s] Allocating page list %u with %u pages", __FUNCTION__,
         id_, num_pages_);

  page_physical_addrsess_ =
      AllocateMemory<PHYSICAL_ADDRESS>(miniport_handle_, num_pages_);
  if (!page_physical_addrsess_) {
    DEBUGP(GVNIC_ERROR,
           "[%s] ERROR: Memory allocation failed for page physical addr list",
           __FUNCTION__);
    return false;
  }

  pages_ = AllocateMemory<PVOID>(miniport_handle_, num_pages_);

  if (!pages_) {
    DEBUGP(GVNIC_ERROR,
           "[%s] ERROR: Memory allocation failed for page virtual addr list",
           __FUNCTION__);
    return false;
  }

  for (UINT i = 0; i < num_pages_; i++) {
    NdisMAllocateSharedMemory(miniport_handle_, PAGE_SIZE, /*cached=*/TRUE,
                              &pages_[i], &page_physical_addrsess_[i]);
    if (!pages_[i]) {
      DEBUGP(GVNIC_ERROR,
             "[%s] ERROR: Memory allocation failed for page count %u",
             __FUNCTION__, i);
      return false;
    }
  }

  return true;
}

void QueuePageList::Release() {
  PAGED_CODE();

  for (UINT i = 0; i < num_pages_; i++) {
    if (pages_[i]) {
      NdisMFreeSharedMemory(miniport_handle_, PAGE_SIZE, /*cached*/ TRUE,
                            pages_[i], page_physical_addrsess_[i]);
    }
  }
  FreeMemory(pages_);
  pages_ = nullptr;
  FreeMemory(page_physical_addrsess_);
  page_physical_addrsess_ = nullptr;
}
