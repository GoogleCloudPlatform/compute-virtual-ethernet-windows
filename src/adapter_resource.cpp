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

#include "adapter_resource.h"  // NOLINT: include directory

#include <ndis.h>

#include "interrupt.h"  // NOLINT: include directory
#include "trace.h"      // NOLINT: include directory

#include "adapter_resource.tmh"  // NOLINT: trace message header

constexpr ULONG kGvnicMaxDmaPhysicalMapping = 0x10000;

namespace {
// Invoked when HAL is done building the scatter/gather.
VOID ProcessSGListHandler(IN PDEVICE_OBJECT device_object, IN PVOID reserved,
                          IN PSCATTER_GATHER_LIST scatter_gather_list,
                          IN PVOID context) {
  UNREFERENCED_PARAMETER(reserved);
  UNREFERENCED_PARAMETER(device_object);
  UNREFERENCED_PARAMETER(scatter_gather_list);
  UNREFERENCED_PARAMETER(context);
}
}  // namespace

NDIS_STATUS AdapterResources::Initialize(NDIS_HANDLE driver_handle,
                                         NDIS_HANDLE miniport_handle,
                                         PNDIS_RESOURCE_LIST ndis_resource_list,
                                         PVOID adapter_context) {
  PAGED_CODE();
  DEBUGP(GVNIC_VERBOSE, "---> AdapterResources::Initialize\n");

  driver_handle_ = driver_handle;
  miniport_handle_ = miniport_handle;

  // Find resource
  int bar_idx = 0;
  for (ULONG i = 0; i < ndis_resource_list->Count; ++i) {
    ULONG type = ndis_resource_list->PartialDescriptors[i].Type;

    if (type == CmResourceTypeMemory) {
      bars_[bar_idx].start =
          ndis_resource_list->PartialDescriptors[i].u.Memory.Start;
      bars_[bar_idx].length =
          ndis_resource_list->PartialDescriptors[i].u.Memory.Length;
      DEBUGP(GVNIC_INFO, "[%s] Found memory at %08llX(%d)\n", __FUNCTION__,
             bars_[bar_idx].start.QuadPart, bars_[bar_idx].length);
      bar_idx++;
    } else if (type == CmResourceTypeInterrupt) {
      if (ndis_resource_list->PartialDescriptors[i].Flags &
          CM_RESOURCE_INTERRUPT_MESSAGE) {
        ULONG msi_vector = ndis_resource_list->PartialDescriptors[i]
                               .u.MessageInterrupt.Translated.Vector;
        ULONG msi_level = ndis_resource_list->PartialDescriptors[i]
                              .u.MessageInterrupt.Translated.Level;
        KAFFINITY msi_affinity = ndis_resource_list->PartialDescriptors[i]
                                     .u.MessageInterrupt.Translated.Affinity;
        DEBUGP(GVNIC_INFO,
               "[%s] Found Interrupt vector %d, level %d, affinity %#llX",
               __FUNCTION__, msi_vector, msi_level, msi_affinity);
      } else {
        DEBUGP(GVNIC_INFO, "[%s] Ignore line-based interrupt.", __FUNCTION__);
      }
    }
  }

  NDIS_STATUS status = NDIS_STATUS_SUCCESS;
  if (bar_idx != kGvnicBarCount) {
    status = NDIS_STATUS_RESOURCE_CONFLICT;
  }

  // Map bars to virtual memory.
  for (int i = 0; status == NDIS_STATUS_SUCCESS && i < kGvnicBarCount; i++) {
    status = NdisMMapIoSpace(&bars_[i].virtual_address, miniport_handle_,
                             bars_[i].start, bars_[i].length);
  }

  // Allocate NET_BUFFER_LIST
  if (status == NDIS_STATUS_SUCCESS) {
    status = AllocateNetBufferListPool();
    DEBUGP(GVNIC_INFO, "[%s] Allocate netbufferlist pool return 0x%08x\n",
           __FUNCTION__, status);
  }

  // Set DMA.
  if (status == NDIS_STATUS_SUCCESS) {
    status = RegisterDma();
    DEBUGP(GVNIC_INFO, "[%s] Register DMA return 0x%08x\n", __FUNCTION__,
           status);
  }

  // Register interrupt.
  if (status == NDIS_STATUS_SUCCESS) {
    status = RegisterInterrupt(adapter_context);
    DEBUGP(GVNIC_INFO, "[%s] Register interrupt return 0x%08x\n", __FUNCTION__,
           status);
  }

  DEBUGP(GVNIC_VERBOSE, "<--- AdapterResources::Initialize status 0x%08x\n",
         status);
  return status;
}

AdapterResources::~AdapterResources() {
  PAGED_CODE();

  Release();
}

void AdapterResources::WriteDoorbell(UINT32 doorbell_index, UINT32 value) {
  WriteRegister(kDoorbellRegister, sizeof(UINT32) * doorbell_index,
                RtlUlongByteSwap(value));
}

void AdapterResources::Release() {
  PAGED_CODE();

  for (int i = 0; i < kGvnicBarCount; i++) {
    if (bars_[i].virtual_address != nullptr) {
      NdisMUnmapIoSpace(miniport_handle_, bars_[i].virtual_address,
                        bars_[i].length);
      bars_[i].virtual_address = nullptr;
    }
  }

  if (buffer_list_pool_ != nullptr) {
    NdisFreeNetBufferListPool(buffer_list_pool_);
    buffer_list_pool_ = nullptr;
  }
  if (dma_handle_ != nullptr) {
    NdisMDeregisterScatterGatherDma(dma_handle_);
    dma_handle_ = nullptr;
  }
  if (interrupt_handle_ != nullptr) {
    NdisMDeregisterInterruptEx(interrupt_handle_);
    interrupt_handle_ = nullptr;
  }
}

NDIS_STATUS AdapterResources::AllocateNetBufferListPool() {
  NET_BUFFER_LIST_POOL_PARAMETERS pool_params;
  pool_params.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
  pool_params.Header.Size = sizeof(pool_params);
  pool_params.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
  pool_params.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT;
  pool_params.fAllocateNetBuffer = TRUE;
  pool_params.ContextSize = 0;
  pool_params.PoolTag = kGvnicMemoryTag;
  pool_params.DataSize = 0;
  buffer_list_pool_ =
      NdisAllocateNetBufferListPool(miniport_handle_, &pool_params);

  if (buffer_list_pool_ == NULL) {
    return NDIS_STATUS_RESOURCES;
  }

  return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS AdapterResources::RegisterDma() {
  NDIS_SG_DMA_DESCRIPTION dma_description;
  dma_description.Header.Type = NDIS_OBJECT_TYPE_SG_DMA_DESCRIPTION;
  dma_description.Header.Revision = NDIS_SG_DMA_DESCRIPTION_REVISION_1;
  dma_description.Header.Size = sizeof(dma_description);
  // NIC can use 64-bit addressing.
  dma_description.Flags = NDIS_SG_DMA_64_BIT_ADDRESS;
  dma_description.MaximumPhysicalMapping = kGvnicMaxDmaPhysicalMapping;
  dma_description.ProcessSGListHandler = ProcessSGListHandler;
  dma_description.SharedMemAllocateCompleteHandler = NULL;
  dma_description.ScatterGatherListSize = 0;
  return NdisMRegisterScatterGatherDma(miniport_handle_, &dma_description,
                                       &dma_handle_);
}

NDIS_STATUS AdapterResources::RegisterInterrupt(PVOID adapter_context) {
  NDIS_MINIPORT_INTERRUPT_CHARACTERISTICS interrupt_chars;
  NdisZeroMemory(&interrupt_chars, sizeof(interrupt_chars));
  interrupt_chars.Header.Type = NDIS_OBJECT_TYPE_MINIPORT_INTERRUPT;
  interrupt_chars.Header.Revision = NDIS_MINIPORT_INTERRUPT_REVISION_1;
  interrupt_chars.Header.Size =
      NDIS_SIZEOF_MINIPORT_INTERRUPT_CHARACTERISTICS_REVISION_1;
  interrupt_chars.DisableInterruptHandler = MiniportDisableInterruptEx;
  interrupt_chars.EnableInterruptHandler = MiniportEnableInterruptEx;
  interrupt_chars.InterruptDpcHandler = MiniportInterruptDPC;
  interrupt_chars.InterruptHandler = MiniportInterrupt;
  interrupt_chars.MsiSupported = TRUE;
  interrupt_chars.MsiSyncWithAllMessages = FALSE;
  interrupt_chars.EnableMessageInterruptHandler = MiniportEnableMSIInterrupt;
  interrupt_chars.DisableMessageInterruptHandler = MiniportDisableMSIInterrupt;
  interrupt_chars.MessageInterruptHandler = MiniportMSIInterrupt;
  interrupt_chars.MessageInterruptDpcHandler = MiniportMSIInterruptDpc;
  NDIS_STATUS status = NdisMRegisterInterruptEx(
      miniport_handle_, adapter_context, &interrupt_chars, &interrupt_handle_);

  if (status != NDIS_STATUS_SUCCESS) {
    return status;
  }

  if (interrupt_chars.InterruptType != NDIS_CONNECT_MESSAGE_BASED ||
      interrupt_chars.MessageInfoTable->MessageCount == 0) {
    DEBUGP(GVNIC_ERROR, "[%s] ERROR: gVNIC needs to have MSIX support.",
           __FUNCTION__);
    return NDIS_STATUS_RESOURCE_CONFLICT;
  }

  msi_info_table_ = interrupt_chars.MessageInfoTable;
  DEBUGP(GVNIC_INFO,
         "[%s] Register return interrupts with count %d and level %#X",
         __FUNCTION__, msi_info_table_->MessageCount,
         (ULONG)msi_info_table_->UnifiedIrql);

  return status;
}
