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

#ifndef MINIPORT_H_
#define MINIPORT_H_

#include <ndis.h>

#ifndef MAJOR_DRIVER_VERSION
#error MAJOR_DRIVER_VERSION not defined
#endif

#ifndef MINOR_DRIVER_VERSION
#error MINOR_DRIVER_VERSION not defined
#endif

#ifndef RELEASE_VERSION
#error RELEASE_VERSION not defined
#endif

#ifndef RELEASE_VERSION_QEF
#error RELEASE_VERSION_QEF not defined
#endif

constexpr int kVendorId = 0x1AE0;  // Google
constexpr char kVendorName[] = "Google";

extern "C" {
// Driver Entry Point. Called by kernel to register driver object.
NDIS_STATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
                        _In_ PUNICODE_STRING RegistryPath);

// Performs operations that are necessary before the system unloads the driver.
MINIPORT_UNLOAD DriverUnload;

// To register optional services.
SET_OPTIONS GvnicSetOptions;
}

#endif  // MINIPORT_H_
