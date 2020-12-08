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

#include "miniport.h"  // NOLINT: include directory

#include <ndis.h>

#include "adapter.h"  // NOLINT: include directory
#include "oid.h"      // NOLINT: include directory
#include "trace.h"    // NOLINT: include directory

#include "miniport.tmh"  // NOLINT: trace message header

NDIS_HANDLE DriverHandle = nullptr;

// Driver Entry Point. Called by kernel to register driver object.
// Arguments:
//   DriverObject - Pointer to driver object created by system.
//   RegistryPath - Pointer to the Unicode name of the registry path.
//
// Returns:
//   NT Status code.
NDIS_STATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
            _In_ PUNICODE_STRING RegistryPath) {
  PAGED_CODE();

  NDIS_MINIPORT_DRIVER_CHARACTERISTICS driver_chars;

  WPP_INIT_TRACING(DriverObject, RegistryPath);

  DEBUGP(GVNIC_VERBOSE, "---> DriverEntry - Version %u.%u",
         MAJOR_DRIVER_VERSION, MINOR_DRIVER_VERSION);

  NdisZeroMemory(&driver_chars, sizeof(driver_chars));

#if NDIS_SUPPORT_NDIS620
  driver_chars.Header.Type = NDIS_OBJECT_TYPE_MINIPORT_DRIVER_CHARACTERISTICS;
  driver_chars.Header.Size =
      NDIS_SIZEOF_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_2;
  driver_chars.Header.Revision =
      NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_2;
#elif NDIS_SUPPORT_NDIS6
  driver_chars.Header.Type = NDIS_OBJECT_TYPE_MINIPORT_DRIVER_CHARACTERISTICS;
  driver_chars.Header.Size =
      NDIS_SIZEOF_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_1;
  driver_chars.Header.Revision =
      NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_1;
#endif  // NDIS MINIPORT VERSION

  driver_chars.MajorNdisVersion = NDIS_MINIPORT_MAJOR_VERSION;
  driver_chars.MinorNdisVersion = NDIS_MINIPORT_MINOR_VERSION;

  driver_chars.MajorDriverVersion =
      static_cast<UINT8>(MAJOR_DRIVER_VERSION & 0xFF);
  driver_chars.MinorDriverVersion =
      static_cast<UINT8>(MINOR_DRIVER_VERSION & 0xFF);

  driver_chars.Flags = 0;

  // Optional Handlers
  driver_chars.SetOptionsHandler = GvnicSetOptions;
  // Not required for virtual driver.
  driver_chars.CheckForHangHandlerEx = NULL;
  driver_chars.ResetHandlerEx = NULL;

  // Required Handlers
  driver_chars.InitializeHandlerEx = GvnicInitialize;
  driver_chars.HaltHandlerEx = GvnicHalt;
  driver_chars.UnloadHandler = DriverUnload;
  driver_chars.PauseHandler = GvnicPause;
  driver_chars.RestartHandler = GvnicRestart;
  driver_chars.OidRequestHandler = GvnicOidRequest;
  driver_chars.SendNetBufferListsHandler = GvnicSendNetBufferLists;
  driver_chars.ReturnNetBufferListsHandler = GvnicReturnNetBufferLists;
  driver_chars.CancelSendHandler = GvnicCancelSendNetBufferLists;
  driver_chars.DevicePnPEventNotifyHandler = GvnicDevicePnPEvent;
  driver_chars.ShutdownHandlerEx = GvnicAdapterShutdown;
  driver_chars.CancelOidRequestHandler = GvnicOidCancelRequest;

#if NDIS_SUPPORT_NDIS61
  driver_chars.DirectOidRequestHandler = NULL;
  driver_chars.CancelDirectOidRequestHandler = NULL;
#endif  // NDIS_SUPPORT_NDIS61

  NDIS_STATUS status = NdisMRegisterMiniportDriver(
      DriverObject, RegistryPath, NULL, &driver_chars, &DriverHandle);
  if (status != NDIS_STATUS_SUCCESS) {
    DEBUGP(GVNIC_ERROR, "NdisMRegisterMiniportDriver failed: %d\n", status);
    DriverUnload(DriverObject);
  }

  DEBUGP(GVNIC_VERBOSE, "<--- DriverEntry status 0x%08x\n", status);
  return status;
}

// Unload Driver. Free all allocated resources, etc.
//
// Arguments:
//   DriverObject - pointer to a driver object.
_Use_decl_annotations_ VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
  PAGED_CODE();
  DEBUGP(GVNIC_VERBOSE, "---> DriverUnload");

  if (DriverHandle != nullptr) {
    DEBUGP(GVNIC_VERBOSE, "Calling NdisMDeregisterMiniportDriver...");
    NdisMDeregisterMiniportDriver(DriverHandle);
  }

  DEBUGP(GVNIC_VERBOSE, "<--- DriverUnload");
  WPP_CLEANUP(DriverObject);
}

// The entry point for the caller's MiniportSetOptions to register optional
// services.
//
// Arguments:
//   miniport_driver_handle - A handle that identifies this miniport driver.
//   miniport_driver_context - The handle identifies the driver context area.
//
// Returns:
//   NT Status code.
_Use_decl_annotations_ NDIS_STATUS
GvnicSetOptions(_In_ NDIS_HANDLE miniport_driver_handle,
                _In_ NDIS_HANDLE miniport_driver_context) {
  PAGED_CODE();
  UNREFERENCED_PARAMETER(miniport_driver_context);
  DEBUGP(GVNIC_VERBOSE, "---> GvnicSetOptions\n");

  NDIS_MINIPORT_PNP_CHARACTERISTICS pnp_chars;
  pnp_chars.Header.Type = NDIS_OBJECT_TYPE_MINIPORT_PNP_CHARACTERISTICS;
  pnp_chars.Header.Revision = NDIS_MINIPORT_PNP_CHARACTERISTICS_REVISION_1;
  pnp_chars.Header.Size = NDIS_SIZEOF_MINIPORT_PNP_CHARACTERISTICS_REVISION_1;
  pnp_chars.MiniportAddDeviceHandler = GvnicAddDevice;
  pnp_chars.MiniportRemoveDeviceHandler = GvnicRemoveDevice;
  pnp_chars.MiniportStartDeviceHandler = GvnicStartDevice;
  pnp_chars.MiniportFilterResourceRequirementsHandler = GvnicFilterResource;

  NDIS_STATUS status = NdisSetOptionalHandlers(
      miniport_driver_handle, (PNDIS_DRIVER_OPTIONAL_HANDLERS)&pnp_chars);

  DEBUGP(GVNIC_INFO, "<--- GvnicSetOptions status = 0x%08x\n", status);
  return status;
}
