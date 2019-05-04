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

// A list of functions for setting, updating offload.
#ifndef OFFLOAD_CONFIG_H_
#define OFFLOAD_CONFIG_H_

#include <ndis.h>

#include "adapter_configuration.h"  // NOLINT: include directory
#include "netutils.h"               // NOLINT: include directory

#if NDIS_SUPPORT_NDIS630
#define SUPPORT_RSC
#endif

// Set default hardware offload to default_offload.
void SetHardwareDefaultOffloadCapability(NDIS_OFFLOAD* default_offload);

// Set init offload configuration based on the registry keys read from
// AdapterConfiguration.
void SetOffloadConfiguration(const AdapterConfiguration& adapter_config,
                             NDIS_OFFLOAD* offload_config);

// Update offload_config based on NDIS_OFFLOAD_ENCAPSULATION. If any change is
// made, it will send offload status change indication to NDIS.
// Params:
//  - offload_capability[in]: hardware offload capability.
//  - encapsulation[in]: encapsulation from OID request to change the config.
//  - miniport_handle[in]: handle used for sending statues indication only.
//  - offload_config[in,out]: current config. Change will be make on this.
//
// Returns:
//  NDIS_STATUS_INVALID_PARAMETER if the request is not compatible with
//  hardware capability.
//  NDIS_STATUS_SUCCESS if change is successfully made to offload_config.
NDIS_STATUS UpdateOffloadConfigFromEncapsulation(
    const NDIS_OFFLOAD& offload_capability,
    NDIS_OFFLOAD_ENCAPSULATION encapsulation, NDIS_HANDLE miniport_handle,
    NDIS_OFFLOAD* offload_config);

// Update offload_config based on NDIS_OFFLOAD_PARAMETERS. If any change is
// made, it will send offload status change indication to NDIS.
// Params:
//  - offload_capability[in]: hardware offload capability.
//  - offload_parameters[in]: NDIS_OFFLOAD_PARAMETERS from OID request to change
//  the config.
//  - miniport_handle[in]: handle used for sending statues indication only.
//  - offload_config[in,out]: current config. Change will be make on this.
//
// Returns:
//  NDIS_STATUS_INVALID_PARAMETER if the request is not compatible with
//  hardware capability.
//  NDIS_STATUS_SUCCESS if change is successfully made to offload_config.
NDIS_STATUS UpdateOffloadConfigFromOffloadParameters(
    const NDIS_OFFLOAD& offload_capability,
    NDIS_OFFLOAD_PARAMETERS offload_parameters, NDIS_HANDLE miniport_handle,
    NDIS_OFFLOAD* offload_config);

void LogOffloadSetting(const char* message, const NDIS_OFFLOAD& offload);
#endif  // OFFLOAD_CONFIG_H_
