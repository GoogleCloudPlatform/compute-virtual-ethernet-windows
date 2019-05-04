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

#ifndef ADMIN_QUEUE_H_
#define ADMIN_QUEUE_H_

#include "abi.h"                // NOLINT: include directory
#include "adapter_resource.h"   // NOLINT: include directory
#include "queue_page_list.h"    // NOLINT: include directory
#include "rss_configuration.h"  // NOLINT: include directory
#include "shared_memory.h"      // NOLINT: include directory
#include "tx_ring.h"            // NOLINT: include directory

struct AdminQueueCommandEntry {
  UINT32 command_id;
  AdminQueueCommand* command;
};

// Class for admin queue setup and use it to query/configure device.
class AdminQueue final {
 public:
  AdminQueue()
      : resources_(nullptr), commands_created_(0), commands_completed_(0) {}
  ~AdminQueue();

  // Not copyable or movable
  AdminQueue(const AdminQueue&) = delete;
  AdminQueue& operator=(const AdminQueue&) = delete;

  NDIS_STATUS Init(AdapterResources* resources);

  // Call DescribeDevice abi to gVNIC device and save the return device
  // descriptor into descriptor param.
  NDIS_STATUS DescribeDevice(DeviceDescriptor* descriptor);

  // Call ConfigureDeviceResource abi to gVnic with following params:
  // - counter_array_addr: physical address of allocated counter array.
  // - num_counters: the length of counter array.
  // - irq_doorbell_addr_base: physical address of allocated notify blocks.
  // - num_irq_doorbells: length of notify block array.
  // - irq_block_size: size of each notify block.
  // - notify_blk_msix_base_idx: notify block start index.
  NDIS_STATUS ConfigureDeviceResource(UINT64 counter_array_addr,
                                      UINT32 num_counters,
                                      UINT64 irq_doorbell_addr_base,
                                      UINT32 num_irq_doorbells,
                                      UINT32 irq_block_size,
                                      UINT32 notify_blk_msix_base_idx);

  // Tell the device to release all resources.
  NDIS_STATUS DeconfigureDeviceResource();

  // Register page list allocated by the driver with the device.
  NDIS_STATUS RegisterPageList(const QueuePageList& page_list,
                               NDIS_HANDLE miniport_handle);

  // Remove the given page list from the device registry. Driver needs to make
  // sure no queue is using it.
  NDIS_STATUS UnregisterPageList(const QueuePageList& page_list);

  // Creates and adds the described tx queue to the Registry.
  NDIS_STATUS CreateTransmitQueue(const TxRing& tx_ring);

  // Creates and adds the described rx queue to the Registry.
  NDIS_STATUS CreateReceiveQueue(const RxRing& rx_ring);

  // Removes the specified tx queue from the registry.
  NDIS_STATUS DestroyTransmitQueue(const TxRing& tx_ring);

  // Removes the specified rx queue from the registry.
  NDIS_STATUS DestroyReceiveQueue(const RxRing& rx_ring);

  // Pass RSS configuration to device.
  NDIS_STATUS SetRssParameters(const RSSConfiguration& rss_config);

  void Release();

  // Write 0x0 to ADMIN_QUEUE_PFN to cause a reset on the device.
  void Reset();

 private:
  // Allocate a AdminCommand object from command_ring_.
  // Return NDIS_STATUS_RESOURCES if no command can be allocated.
  NDIS_STATUS CreateCommand(AdminQueueCommandEntry* command_entry);

  // Execute and wait for the command to be executed by device.
  NDIS_STATUS ExecuteCommand(const AdminQueueCommandEntry& command_entry);

  // Notify device that command is ready for execution.
  void RingDoorbell(UINT32 command_id);

  // Wait for the current command to run.
  // commands_completed_ will be updated with the value read from device.
  // Return false if timeout and true otherwise.
  bool WaitForCommand(UINT32 command_id);

  AdapterResources* resources_;

  // Shared memory between device and driver for sending command and receiving
  // result.
  SharedMemory<AdminQueueCommand> command_ring_;

  UINT32 commands_created_;
  UINT32 commands_completed_;
};

#endif  // ADMIN_QUEUE_H_
