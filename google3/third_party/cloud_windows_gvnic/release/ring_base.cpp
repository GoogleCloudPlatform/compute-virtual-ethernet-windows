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

#include "ring_base.h"  // NOLINT: include directory

#include "abi.h"                 // NOLINT: include directory
#include "adapter_resource.h"    // NOLINT: include directory
#include "adapter_statistics.h"  // NOLINT: include directory
#include "trace.h"               // NOLINT: include directory

#include "ring_base.tmh"  // NOLINT: trace message header

RingBase::~RingBase() { Release(); }

bool RingBase::Init(UINT32 id, UINT32 slice, UINT32 traffic_class,
                    QueuePageList* queue_page_list, UINT32 notify_id,
                    AdapterResources* adapter_resource,
                    AdapterStatistics* statistics,
                    const DeviceCounter* device_counters) {
  PAGED_CODE();

  id_ = id;
  slice_ = slice;
  traffic_class_ = traffic_class;
  queue_page_list_ = queue_page_list;
  notify_id_ = notify_id;
  adapter_resource_ = adapter_resource;
  adapter_statistics_ = statistics;
  device_counters_ = device_counters;

  if (!resources_.Allocate(adapter_resource_->miniport_handle())) {
    DEBUGP(GVNIC_ERROR,
           "[%s] ERROR: Memory allocation failed for queue resource.",
           __FUNCTION__);
    return false;
  }

  is_init_ = true;
  return true;
}

void RingBase::Release() {
  PAGED_CODE();
  resources_.Release();
  is_init_ = false;
}

void RingBase::WriteDoorbell(ULONG value) {
  KeMemoryBarrier();
  UINT32 doorbell_idx = GetDoorbellIndex();
  adapter_resource_->WriteDoorbell(doorbell_idx, value);

  // The only scenario that the doorbell index gets changed is that device
  // backend switches the queue between software and hardware bypass. If it
  // happens after driver read the doorbell, driver could write the value to a
  // wrong place. Read it again here to cover the scenario.
  //
  // Driver doesn't need to do another retry as the backend switch happens
  // really rarely and it is almost impossible to happen twice within two
  // register read.
  UINT32 doorbell_idx_check = GetDoorbellIndex();
  if (doorbell_idx != doorbell_idx_check) {
    adapter_resource_->WriteDoorbell(doorbell_idx_check, value);
  }
}

UINT32 RingBase::ReadPacketsSent() {
  // TODO: flush the memory before read.
  KeMemoryBarrier();
  UINT32 counter_idx = GetDeviceCounterIndex();

  // We don't do counter check here as WriteDoorbell. If it is moved, the
  // counter won't be reset to zero so driver just gets an old value. Next
  // read will get it from correct location.
  return RtlUlongByteSwap(device_counters_[counter_idx].packets_sent);
}

UINT32 RingBase::GetDoorbellIndex() const {
  return RtlUlongByteSwap(resources_.virtual_address()->doorbell_index);
}

UINT32 RingBase::GetDeviceCounterIndex() const {
  return RtlUlongByteSwap(resources_.virtual_address()->counter_index);
}
