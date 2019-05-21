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

#ifndef ADAPTER_H_
#define ADAPTER_H_

#include <ndis.h>

#include "adapter_configuration.h"  // NOLINT: include directory
#include "adapter_resource.h"       // NOLINT: include directory
#include "adapter_statistics.h"     // NOLINT: include directory
#include "gvnic_pci_device.h"       // NOLINT: include directory

// Structure to hold core contents across callbacks.
struct AdapterContext {
  // Resource the adapter is holding.
  AdapterResources resources;

  // Configurations from registry.
  AdapterConfiguration configuration;

  // Holding Statistics data.
  AdapterStatistics statistics;

  // Physical NIC device object.
  GvnicPciDevice device;
};

// Declare callback functions with role type.
// Learn more:
// https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/static-driver-verifier-ndis-function-declarations
extern "C" {
// To establish a context area for an added device
MINIPORT_ADD_DEVICE GvnicAddDevice;

// To modify the resource requirements for a device.
MINIPORT_FILTER_RESOURCE_REQUIREMENTS GvnicFilterResource;

// Called before MiniportInitializeEx to clean up resource modified by
// GvnicFilterResource.
MINIPORT_START_DEVICE GvnicStartDevice;

// To releases resources that the MiniportAddDevice function allocated.
MINIPORT_REMOVE_DEVICE GvnicRemoveDevice;

// Called by NDIS to initialize a miniport adapter for network I/O operations.
MINIPORT_INITIALIZE GvnicInitialize;

// Called by NDIS to free resources when a miniport adapter is removed,
// and to stop the hardware.
MINIPORT_HALT GvnicHalt;

// Called by NDIS to request the driver to release resources before the system
// completes a driver unload operation.
MINIPORT_UNLOAD GvnicUnload;

// Called by NDIS to stop the flow of network data.
MINIPORT_PAUSE GvnicPause;

// Initiates a restart request for a miniport adapter that is paused.
MINIPORT_RESTART GvnicRestart;

// Called by NDIS when the system is shutting down.
MINIPORT_SHUTDOWN GvnicAdapterShutdown;

// Called by NDIS to notify the driver of Plug and Play (PnP) events.
MINIPORT_DEVICE_PNP_EVENT_NOTIFY GvnicDevicePnPEvent;

// NDIS calls the MiniportSendNetBufferLists function to transmit network data
// that is contained in a linked list of NET_BUFFER_LIST structures.
MINIPORT_SEND_NET_BUFFER_LISTS GvnicSendNetBufferLists;

// Called by NDIS to cancel the transmission of all NET_BUFFER_LIST structures
// that are marked with a specified cancellation identifier.
MINIPORT_CANCEL_SEND GvnicCancelSendNetBufferLists;

// NDIS calls the MiniportReturnNetBufferLists function to return ownership of
// NET_BUFFER_LIST structures, associated NET_BUFFER structures, and any
// attached MDLs to a miniport driver.
MINIPORT_RETURN_NET_BUFFER_LISTS GvnicReturnNetBufferLists;
}

#endif  // ADAPTER_H_
