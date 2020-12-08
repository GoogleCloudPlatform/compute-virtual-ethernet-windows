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

#ifndef DEVICE_PARAMETERS_H_
#define DEVICE_PARAMETERS_H_

#include "abi.h"  // NOLINT: include directory

// Struct for holding max package size configuration.
struct MaxPacketSize {
  UINT max_data_size;
  UINT max_full_size;
};

// Struct for holding configurations from gvnic device.
struct GvnicDeviceParameters {
  UINT32 max_tx_queues;
  UINT32 max_rx_queues;
  bool support_raw_addressing;
  DeviceDescriptor descriptor;
};

struct QueueConfig {
  UINT32 max_queues;
  UINT32 num_queues;
  UINT32 array_size;
  UINT32 max_slices;
  UINT32 num_slices;
  union {
    struct {
      UINT32 num_traffic_class;
      UINT32 max_traffic_class;
    } tx;
    struct {
      UINT32 num_groups;
    } rx;
  };
  UINT32 num_descriptors;
  UINT32 pages_per_queue_page_list;
};

#endif  // DEVICE_PARAMETERS_H_
