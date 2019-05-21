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

#include "admin_queue.h"  // NOLINT: include directory

#include <ndis.h>

#include "abi.h"               // NOLINT: include directory
#include "adapter_resource.h"  // NOLINT: include directory
#include "rx_ring.h"           // NOLINT: include directory
#include "shared_memory.h"     // NOLINT: include directory
#include "trace.h"             // NOLINT: include directory
#include "tx_ring.h"           // NOLINT: include directory

#include "admin_queue.tmh"  // NOLINT: include directory

namespace {
// Version of DescribeDeviceCommand.
constexpr UINT32 kDescribeDeviceVersion = 1;

constexpr ULONG kAdminQueueSize = PAGE_SIZE;
constexpr int kAdminQueueMaxCommand = kAdminQueueSize / kAdminQeueueCommandSize;

// Device will trigger reset if Admin Queue page frame number is set to 0.
constexpr ULONG kDeviceResetPfn = 0x0;

// Max retries for checking for command_id status.
constexpr int kMaxAdminQueueEventCounterCheck = 100;

}  // namespace

NDIS_STATUS AdminQueue::Init(AdapterResources* resources) {
  PAGED_CODE();

  resources_ = resources;
  if (!command_ring_.Allocate(resources_->miniport_handle(),
                              kAdminQueueMaxCommand)) {
    return NDIS_STATUS_RESOURCES;
  }

  // Cast normal page frame number(52 bits) to ULONG as gVNIC device only takes
  // 32 bits. With this, we can support guest with up to 16TB memory.
  ULONG page_frame_number = static_cast<ULONG>(
      command_ring_.physical_address().QuadPart >> PAGE_SHIFT);

  DEBUGP(GVNIC_INFO, "Write admin_queue_pfn %#X to device", page_frame_number);
  resources_->WriteRegister(kConfigStatusRegister,
                            FIELD_OFFSET(GvnicDeviceConfig, admin_queue_pfn),
                            RtlUlongByteSwap(page_frame_number));

  return NDIS_STATUS_SUCCESS;
}

void AdminQueue::Reset() {
  PAGED_CODE();
  resources_->WriteRegister(kConfigStatusRegister,
                            FIELD_OFFSET(GvnicDeviceConfig, admin_queue_pfn),
                            RtlUlongByteSwap(kDeviceResetPfn));
}

NDIS_STATUS AdminQueue::DescribeDevice(DeviceDescriptor* descriptor) {
  PAGED_CODE();

  AdminQueueCommandEntry command_entry;
  NDIS_STATUS status = CreateCommand(&command_entry);

  if (status != NDIS_STATUS_SUCCESS) {
    return status;
  }

  command_entry.command->opcode = RtlUlongByteSwap(kDescribeDevice);

  SharedMemory<DeviceDescriptor> dma_descriptor;
  if (!dma_descriptor.Allocate(resources_->miniport_handle())) {
    return NDIS_STATUS_RESOURCES;
  }

  command_entry.command->describe_device.device_descriptor_address =
      RtlUlonglongByteSwap(dma_descriptor.physical_address().QuadPart);

  command_entry.command->describe_device.device_descriptor_version =
      RtlUlongByteSwap(kDescribeDeviceVersion);

  command_entry.command->describe_device.available_length =
      RtlUlongByteSwap(sizeof(DeviceDescriptor));

  status = ExecuteCommand(command_entry);

  if (status != NDIS_STATUS_SUCCESS) {
    return status;
  }

  DeviceDescriptor* gvnic_desc = dma_descriptor.virtual_address();

  descriptor->num_rx_groups = RtlUshortByteSwap(gvnic_desc->num_rx_groups);
  descriptor->tx_queue_size = RtlUshortByteSwap(gvnic_desc->tx_queue_size);
  descriptor->rx_queue_size = RtlUshortByteSwap(gvnic_desc->rx_queue_size);
  descriptor->default_num_slices =
      RtlUshortByteSwap(gvnic_desc->default_num_slices);
  descriptor->max_registered_pages =
      RtlUshortByteSwap(gvnic_desc->max_registered_pages);
  descriptor->mtu = RtlUshortByteSwap(gvnic_desc->mtu);
  descriptor->event_counters = RtlUshortByteSwap(gvnic_desc->event_counters);
  descriptor->tx_pages_per_qpl =
      RtlUshortByteSwap(gvnic_desc->tx_pages_per_qpl);
  descriptor->rx_pages_per_qpl =
      RtlUshortByteSwap(gvnic_desc->rx_pages_per_qpl);
  NdisMoveMemory(descriptor->mac, gvnic_desc->mac, sizeof(descriptor->mac));

  DEBUGP(GVNIC_INFO,
         "Get descriptor from device: num_rx_group - %u, tx_queue_size - %u, "
         "rx_queue_size - %u, max_registered_pages - %llu, mtu - %u, "
         "event_counters - %u, default_num_slices - %u",
         descriptor->num_rx_groups, descriptor->tx_queue_size,
         descriptor->rx_queue_size, descriptor->max_registered_pages,
         descriptor->mtu, descriptor->event_counters,
         descriptor->default_num_slices);

  LogMacAddress("Mac from device", descriptor->mac);

  return status;
}

NDIS_STATUS AdminQueue::ConfigureDeviceResource(
    UINT64 counter_array_addr, UINT32 num_counters,
    UINT64 irq_doorbell_addr_base, UINT32 num_irq_doorbells,
    UINT32 irq_block_size, UINT32 notify_blk_msix_base_idx) {
  PAGED_CODE();

  // Both irq_doorbell_addr_base and irq_block_size needs to be cache line
  // aligned.
  NT_ASSERT(irq_doorbell_addr_base % kCacheLineSize == 0);
  NT_ASSERT(irq_block_size % kCacheLineSize == 0);

  AdminQueueCommandEntry command_entry;
  NDIS_STATUS status = CreateCommand(&command_entry);

  if (status != NDIS_STATUS_SUCCESS) {
    return status;
  }

  AdminQueueCommand* command = command_entry.command;

  command->opcode = RtlUlongByteSwap(kConfigureDeviceResources);
  command->configure_device_resources = {
      /*.counter_array=*/RtlUlonglongByteSwap(counter_array_addr),
      /*.irq_db_addr_base=*/RtlUlonglongByteSwap(irq_doorbell_addr_base),
      /*.num_counters=*/RtlUlongByteSwap(num_counters),
      /*.num_irq_dbs=*/RtlUlongByteSwap(num_irq_doorbells),
      /*.irq_db_stride=*/RtlUlongByteSwap(irq_block_size),
      /*.ntfy_blk_msix_base_idx=*/RtlUlongByteSwap(notify_blk_msix_base_idx)};

  return ExecuteCommand(command_entry);
}

NDIS_STATUS AdminQueue::DeconfigureDeviceResource() {
  PAGED_CODE();

  AdminQueueCommandEntry command_entry;
  NDIS_STATUS status = CreateCommand(&command_entry);

  if (status != NDIS_STATUS_SUCCESS) {
    return status;
  }
  command_entry.command->opcode = RtlUlongByteSwap(kDeconfigureDeviceResources);
  return ExecuteCommand(command_entry);
}

NDIS_STATUS AdminQueue::RegisterPageList(const QueuePageList& page_list,
                                         NDIS_HANDLE miniport_handle) {
  PAGED_CODE();

  AdminQueueCommandEntry command_entry;
  NDIS_STATUS status = CreateCommand(&command_entry);

  if (status != NDIS_STATUS_SUCCESS) {
    return status;
  }

  AdminQueueCommand* command = command_entry.command;
  // Device expect 64 bit integer for page physical memory address.
  SharedMemory<ULONGLONG> page_physical_addr_list_dma;
  if (!page_physical_addr_list_dma.Allocate(miniport_handle,
                                            page_list.num_pages())) {
    return NDIS_STATUS_RESOURCES;
  }

  // Copy all physical address of the page list into continues dma memory list.
  // Device will iterate through the list and save a copy of all page physical
  // address.
  ULONGLONG* page_physical_addr_list =
      page_physical_addr_list_dma.virtual_address();
  for (UINT i = 0; i < page_list.num_pages(); i++) {
    page_physical_addr_list[i] =
        RtlUlonglongByteSwap(page_list.page_physical_address()[i].QuadPart);
  }

  command->opcode = RtlUlongByteSwap(kRegisterPageList);
  command->register_page_list = {
      /*.page_list_id=*/RtlUlongByteSwap(page_list.id()),
      /*.num_pages=*/RtlUlongByteSwap(page_list.num_pages()),
      /*.page_list_address=*/
      RtlUlonglongByteSwap(
          page_physical_addr_list_dma.physical_address().QuadPart)};

  return ExecuteCommand(command_entry);
}

NDIS_STATUS AdminQueue::UnregisterPageList(const QueuePageList& page_list) {
  PAGED_CODE();

  AdminQueueCommandEntry command_entry;
  NDIS_STATUS status = CreateCommand(&command_entry);

  if (status != NDIS_STATUS_SUCCESS) {
    return status;
  }

  AdminQueueCommand* command = command_entry.command;

  command->opcode = RtlUlongByteSwap(kUnregisterPageList);
  command->unregister_page_list = {
      /*.page_list_id=*/RtlUlongByteSwap(page_list.id()),
  };

  return ExecuteCommand(command_entry);
}

NDIS_STATUS AdminQueue::CreateTransmitQueue(const TxRing& tx_ring) {
  PAGED_CODE();

  // PageList must be assigned to tx ring.
  NT_ASSERT(tx_ring.queue_page_list() != nullptr);

  AdminQueueCommandEntry command_entry;
  NDIS_STATUS status = CreateCommand(&command_entry);

  if (status != NDIS_STATUS_SUCCESS) {
    return status;
  }

  AdminQueueCommand* command = command_entry.command;

  command->opcode = RtlUlongByteSwap(kCreateTxQueue);
  command->create_transmit_queue = {
      /*.queue_id=*/RtlUlongByteSwap(tx_ring.id()),
      /*.priority=*/RtlUlongByteSwap(tx_ring.traffic_class()),
      /*.queue_resources_addr=*/
      RtlUlonglongByteSwap(tx_ring.ResourcesPhysicalAddress().QuadPart),
      /*.tx_ring_addr=*/
      RtlUlonglongByteSwap(tx_ring.descriptor_ring_physical_address().QuadPart),
      /*.queue_page_list_id=*/RtlUlongByteSwap(tx_ring.queue_page_list()->id()),
      /*.notify_blk_id=*/RtlUlongByteSwap(tx_ring.notify_id())};

  DEBUGP(GVNIC_VERBOSE,
         "[%s] CreateTransmitQueue: id - %u, tc - %u, page_list_id - %u, "
         "notify_id - %u",
         __FUNCTION__, tx_ring.id(), tx_ring.traffic_class(),
         tx_ring.queue_page_list()->id(), tx_ring.notify_id());

  return ExecuteCommand(command_entry);
}

NDIS_STATUS AdminQueue::DestroyTransmitQueue(const TxRing& tx_ring) {
  PAGED_CODE();

  AdminQueueCommandEntry command_entry;
  NDIS_STATUS status = CreateCommand(&command_entry);

  if (status != NDIS_STATUS_SUCCESS) {
    return status;
  }

  AdminQueueCommand* command = command_entry.command;

  command->opcode = RtlUlongByteSwap(kDestroyTxQueue);
  command->destroy_transmit_queue = {
      /*.queue_id=*/RtlUlongByteSwap(tx_ring.id()),
  };

  return ExecuteCommand(command_entry);
}

NDIS_STATUS AdminQueue::CreateReceiveQueue(const RxRing& rx_ring) {
  PAGED_CODE();

  // PageList must be assigned to tx ring.
  NT_ASSERT(rx_ring.queue_page_list() != nullptr);

  AdminQueueCommandEntry command_entry;
  NDIS_STATUS status = CreateCommand(&command_entry);

  if (status != NDIS_STATUS_SUCCESS) {
    return status;
  }

  AdminQueueCommand* command = command_entry.command;

  command->opcode = RtlUlongByteSwap(kCreateRxQueue);
  command->create_receive_queue = {
      /*.queue_id=*/RtlUlongByteSwap(rx_ring.id()),
      /*.slice=*/RtlUlongByteSwap(rx_ring.slice()),
      /*.group=*/RtlUlongByteSwap(rx_ring.traffic_class()),
      /*.notify_blk_id=*/RtlUlongByteSwap(rx_ring.notify_id()),
      /*.queue_resources_addr=*/
      RtlUlonglongByteSwap(rx_ring.ResourcesPhysicalAddress().QuadPart),
      /*.rx_desc_ring_addr=*/
      RtlUlonglongByteSwap(rx_ring.DescriptorRingPhysicalAddr().QuadPart),
      /*.rx_data_ring_addr=*/
      RtlUlonglongByteSwap(rx_ring.DataRingPhysicalAddr().QuadPart),
      /*.queue_page_list_id=*/
      RtlUlongByteSwap(rx_ring.queue_page_list()->id())};

  DEBUGP(GVNIC_VERBOSE,
         "[%s] CreateReceiveQueue: id - %u, slice -%u, tc - %u, "
         "page_list_id - %u, notify_id - %u",
         __FUNCTION__, rx_ring.id(), rx_ring.slice(), rx_ring.traffic_class(),
         rx_ring.queue_page_list()->id(), rx_ring.notify_id());

  return ExecuteCommand(command_entry);
}

NDIS_STATUS AdminQueue::DestroyReceiveQueue(const RxRing& rx_ring) {
  PAGED_CODE();

  AdminQueueCommandEntry command_entry;
  NDIS_STATUS status = CreateCommand(&command_entry);

  if (status != NDIS_STATUS_SUCCESS) {
    return status;
  }

  AdminQueueCommand* command = command_entry.command;

  command->opcode = RtlUlongByteSwap(kDestroyRxQueue);
  command->destroy_receive_queue = {
      /*.queue_id=*/RtlUlongByteSwap(rx_ring.id()),
  };

  return ExecuteCommand(command_entry);
}

AdminQueue::~AdminQueue() {
  PAGED_CODE();

  Release();
}

NDIS_STATUS AdminQueue::SetRssParameters(const RSSConfiguration& rss_config) {
  PAGED_CODE();

  UINT64 hash_secret_key_physical_addr = 0;
  UINT64 indirection_table_physical_addr = 0;
  SharedMemory<UINT8> dma_hash_secret_key;
  SharedMemory<UINT32> dma_indirection_table;

  if (rss_config.is_enabled()) {
    if (!dma_hash_secret_key.Allocate(resources_->miniport_handle(),
                                      rss_config.hash_secret_key_size())) {
      return NDIS_STATUS_RESOURCES;
    }

    NdisMoveMemory(dma_hash_secret_key.virtual_address(),
                   rss_config.hash_secret_key(),
                   rss_config.hash_secret_key_size());
    hash_secret_key_physical_addr =
        dma_hash_secret_key.physical_address().QuadPart;

    if (!dma_indirection_table.Allocate(resources_->miniport_handle(),
                                        rss_config.indirection_table_size())) {
      return NDIS_STATUS_RESOURCES;
    }

    // Device asks for slice id table. Driver keeps processor id and slice id in
    // sync so we can just use the processor number here.
    UINT32* device_indirection_table = dma_indirection_table.virtual_address();
    for (UINT i = 0; i < rss_config.indirection_table_size(); i++) {
      device_indirection_table[i] =
          RtlUlongByteSwap(rss_config.indirection_table()[i].Number);
    }
    indirection_table_physical_addr =
        dma_indirection_table.physical_address().QuadPart;
  }

  AdminQueueCommandEntry command_entry;
  NDIS_STATUS status = CreateCommand(&command_entry);

  if (status != NDIS_STATUS_SUCCESS) {
    return status;
  }

  AdminQueueCommand* command = command_entry.command;
  // The recalculated hash_type_ value that matches the format used by device.
  UINT16 rematched_hash_type =
      (UINT16)rss_config.hash_type() >> kRssHashTypeShift;

  command->opcode = RtlUlongByteSwap(kSetWindowsRssParameters);
  command->set_rss_parameters = {
      /*.supported_hash_type=*/RtlUshortByteSwap(rematched_hash_type),
      /*.hash_function=*/rss_config.hash_func(),
      /*.reserved=*/0,
      /*.hash_secret_key_size=*/
      RtlUshortByteSwap(rss_config.hash_secret_key_size()),
      /*.queue_indirection_table_size=*/
      RtlUshortByteSwap(rss_config.indirection_table_size()),
      /*.hash_secret_key_addr=*/
      RtlUlonglongByteSwap(hash_secret_key_physical_addr),
      /*.queue_indirection_table_addr=*/
      RtlUlonglongByteSwap(indirection_table_physical_addr),
  };

  return ExecuteCommand(command_entry);
}

void AdminQueue::Release() {
  PAGED_CODE();

  Reset();
  command_ring_.Release();
}

NDIS_STATUS AdminQueue::CreateCommand(AdminQueueCommandEntry* command_entry) {
  PAGED_CODE();

  command_entry->command_id =
      InterlockedIncrement(reinterpret_cast<LONG*>(&commands_created_));

  if (commands_created_ - commands_completed_ >= kAdminQueueMaxCommand) {
    command_entry->command = nullptr;
    InterlockedDecrement(reinterpret_cast<LONG*>(&commands_created_));
    return NDIS_STATUS_RESOURCES;
  }
  command_entry->command = command_ring_.virtual_address() +
                           (commands_created_ - 1) % kAdminQueueMaxCommand;

  NdisZeroMemory(command_entry->command, kAdminQeueueCommandSize);

  return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS AdminQueue::ExecuteCommand(
    const AdminQueueCommandEntry& command_entry) {
  PAGED_CODE();

  DEBUGP(GVNIC_INFO, "[%s] Executing command with opcode %#X", __FUNCTION__,
         RtlUlongByteSwap(command_entry.command->opcode));

  RingDoorbell(command_entry.command_id);

  if (!WaitForCommand(command_entry.command_id)) {
    DEBUGP(GVNIC_ERROR,
           "[%s] Error: Wait for admin queue command execution timeout",
           __FUNCTION__);
    return NDIS_STATUS_FAILURE;
  }

  KeMemoryBarrier();
  UINT32 execute_status = RtlUlongByteSwap(command_entry.command->status);

  if (execute_status != kAdminQueueCommandPassed) {
    DEBUGP(GVNIC_ERROR,
           "[%s] Error: Execute command %#X failed with status %#X",
           __FUNCTION__, RtlUlongByteSwap(command_entry.command->opcode),
           execute_status);

    if (execute_status == kAdminQueueCommandUnimplementedError) {
      return NDIS_STATUS_NOT_SUPPORTED;
    }

    return NDIS_STATUS_FAILURE;
  }

  return NDIS_STATUS_SUCCESS;
}

void AdminQueue::RingDoorbell(UINT32 command_id) {
  PAGED_CODE();

  DEBUGP(GVNIC_INFO, "[%s] Ring doorbell for command %u", __FUNCTION__,
         command_id);

  KeMemoryBarrier();
  resources_->WriteRegister(
      kConfigStatusRegister,
      FIELD_OFFSET(GvnicDeviceConfig, admin_queue_doorbell),
      RtlUlongByteSwap(command_id));
}

bool AdminQueue::WaitForCommand(UINT32 command_id) {
  PAGED_CODE();

  for (int i = 0; i < kMaxAdminQueueEventCounterCheck; i++) {
    ULONG event_counter;
    resources_->ReadRegister(
        kConfigStatusRegister,
        FIELD_OFFSET(GvnicDeviceConfig, admin_queue_event_counter),
        &event_counter);

    commands_completed_ = RtlUlongByteSwap(event_counter);

    if (commands_completed_ >= command_id) {
      return true;
    }
  }

  return false;
}
