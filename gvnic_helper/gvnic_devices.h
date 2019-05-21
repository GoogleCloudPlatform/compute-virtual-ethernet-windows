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

#ifndef GVNIC_DEVICES_H_
#define GVNIC_DEVICES_H_

// clang-format off
#include <windows.h>
#include <setupapi.h>
// clang-format on

#include <iostream>
#include <vector>

using std::string;
using std::vector;

// To store gvnic device information
struct GvnicDeviceInfo {
  string device_instanceid;
  string device_description;
  string device_name;
  string location_info;
  string registry_pathname;
  // number associated with the device that can be displayed in the user
  // interface
  DWORD device_number;
  SP_DEVINFO_DATA device_info;
};

// To get all gvnic devices information
class GvnicDevices {
 public:
  GvnicDevices();

  HDEVINFO GetDevicesInfoSet() { return devices_info_set_; }

  vector<GvnicDeviceInfo> GetGvnicDevices() { return gvnic_devices_; }

  // Not copyable and movable
  GvnicDevices(const GvnicDevices&) = delete;
  GvnicDevices& operator=(const GvnicDevices&) = delete;

  // To initialize the gvnic devices information
  BOOL Init();

 private:
  HDEVINFO devices_info_set_;
  vector<GvnicDeviceInfo> gvnic_devices_;

  BOOL GetNetDeviceClassGuids(vector<GUID>& guids);
  BOOL IsGvnicDevice(const string& device_id);
  string GetDeviceDataStringFromRegistryProperty(
      HDEVINFO handle_device_info, PSP_DEVINFO_DATA device_info_data,
      DWORD property_id);
  DWORD GetDeviceDataDwordFromRegistryProperty(
      HDEVINFO handle_device_info, PSP_DEVINFO_DATA device_info_data,
      DWORD property_id);
  HKEY GetDeviceRegistryKey(HDEVINFO handle_device_info,
                            PSP_DEVINFO_DATA device_info_data);
  BOOL GetDevicesInfoList(GUID* device_class_guids,
                          SP_DEVINFO_LIST_DETAIL_DATA* devices_info_list);
  BOOL GetGvnicDevicesDetailInfo(SP_DEVINFO_LIST_DETAIL_DATA devices_info_list);
};

#endif  // GVNIC_DEVICES_H_
