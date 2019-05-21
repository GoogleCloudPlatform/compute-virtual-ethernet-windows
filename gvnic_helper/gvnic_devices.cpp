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

#include "gvnic_devices.h"  // NOLINT: include directory

#include <cfgmgr32.h>

#include <algorithm>

#include "device_registry.h"  // NOLINT: include directory
#include "gvnic_helper.h"     // NOLINT: include directory

using std::cout;
using std::endl;

constexpr LPCTSTR kNetworkDevicesClass = "net";
constexpr LPCTSTR kGvnicDeviceVendorId = "1AE0";
constexpr LPCTSTR kGvnicDeviceHardwareId = "0042";

GvnicDevices::GvnicDevices() { devices_info_set_ = INVALID_HANDLE_VALUE; }

BOOL DevicesComparator(GvnicDeviceInfo device_1, GvnicDeviceInfo device_2) {
  return device_1.device_instanceid < device_2.device_instanceid;
}

// Get device registry key from device info data.
// SetupDiOpenDevRegKey : opens a registry key for device-specific configuration
// information
HKEY GvnicDevices::GetDeviceRegistryKey(HDEVINFO device_info_set,
                                        PSP_DEVINFO_DATA device_info_data) {
  HKEY hkey = SetupDiOpenDevRegKey(device_info_set, device_info_data,
                                   DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_READ);

  if (hkey == INVALID_HANDLE_VALUE) {
    cout << "GVNICHELPER_ERROR: SetupDiOpenDevRegKey failed with error: "
         << GetErrorMessage(GetLastError()) << endl;
  }

  return hkey;
}

// Get device property data of type DWORD using device info data.
// property to retrieve is mentioned by property_id
// SetupDiGetDeviceRegistryProperty : retrieves a specified Plug and Play device
// property
DWORD GvnicDevices::GetDeviceDataDwordFromRegistryProperty(
    HDEVINFO device_info_set, PSP_DEVINFO_DATA device_info_data,
    DWORD property_id) {
  DWORD device_data;
  DWORD data_type;
  if (!SetupDiGetDeviceRegistryProperty(
          device_info_set, device_info_data, property_id, &data_type,
          (PBYTE)&device_data, sizeof(device_data), NULL)) {
    DWORD error = GetLastError();
    cout << "GVNICHELPER_ERROR: SetupDiGetDeviceRegistryProperty "
            "failed with error: "
         << GetErrorMessage(error) << endl;
    return 0;
  }
  if (data_type != REG_DWORD) {
    cout << "GVNICHELPER_ERROR: SetupDiGetDeviceRegistryProperty "
            "returned incorrect registry type"
         << endl;
    return 0;
  }
  return device_data;
}

// Get device property data of type string using device info data.
string GvnicDevices::GetDeviceDataStringFromRegistryProperty(
    HDEVINFO device_info_set, PSP_DEVINFO_DATA device_info_data,
    DWORD property_id) {
  LPSTR device_data = NULL;
  DWORD size = 0;
  DWORD data_type;

  // First time passing data null and size 0, function would return
  // ERROR_INSUFFICIENT_BUFFER and would fill required size by data in size
  // field
  while (!SetupDiGetDeviceRegistryProperty(device_info_set, device_info_data,
                                           property_id, &data_type,
                                           (PBYTE)device_data, size, &size)) {
    DWORD error = GetLastError();
    if (error != ERROR_INSUFFICIENT_BUFFER) {
      cout << "GVNICHELPER_ERROR: SetupDiGetDeviceRegistryProperty "
              "failed with error: "
           << GetErrorMessage(error) << endl;
      delete[] device_data;
      return string();
    }

    // String should be null terminated before using it
    device_data = new CHAR[(size / sizeof(CHAR)) + 1];
    device_data[size / sizeof(CHAR)] = '\0';
  }

  if (REG_SZ != data_type) {
    cout << "GVNICHELPER_ERROR: SetupDiGetDeviceRegistryProperty "
            "returned incorrect registry type"
         << endl;
    delete[] device_data;
    return string();
  }

  string data(device_data);
  delete[] device_data;
  return data;
}

BOOL GvnicDevices::IsGvnicDevice(const string& device_id) {
  return (device_id.find(string("VEN_") + kGvnicDeviceVendorId) !=
          string::npos) &&
         (device_id.find(string("DEV_") + kGvnicDeviceHardwareId) !=
          string::npos);
}

// Get devices detail info
// SetupDiEnumDeviceInfo : returns a SP_DEVINFO_DATA structure that specifies
//                         a device information element in a device information
//                         set
// CM_Get_Device_ID_Ex : retrieves the device instance ID for a specified device
// instance.
BOOL GvnicDevices::GetGvnicDevicesDetailInfo(
    SP_DEVINFO_LIST_DETAIL_DATA devices_info_list) {
  HDEVINFO devices_info_set = GetDevicesInfoSet();
  vector<GvnicDeviceInfo> devices;

  SP_DEVINFO_DATA current_device_info;
  current_device_info.cbSize = sizeof(current_device_info);

  for (DWORD device_index = 0; SetupDiEnumDeviceInfo(
           devices_info_set, device_index, &current_device_info);
       device_index++) {
    CHAR device_instanceid[MAX_DEVICE_ID_LEN];

    // CM_Get_Device_ID_Ex Function appends NULL terminator to device_instanceid
    CONFIGRET return_value =
        CM_Get_Device_ID_Ex(current_device_info.DevInst, device_instanceid,
                            ARRAY_SIZE(device_instanceid), 0,
                            devices_info_list.RemoteMachineHandle);

    if (return_value == CR_SUCCESS) {
      if (IsGvnicDevice(device_instanceid)) {
        GvnicDeviceInfo device_info;
        device_info.device_instanceid = device_instanceid;
        device_info.device_description =
            GetDeviceDataStringFromRegistryProperty(
                devices_info_set, &current_device_info, SPDRP_DEVICEDESC);
        device_info.device_name = device_info.device_description;
        device_info.location_info = GetDeviceDataStringFromRegistryProperty(
            devices_info_set, &current_device_info, SPDRP_LOCATION_INFORMATION);
        device_info.device_number = GetDeviceDataDwordFromRegistryProperty(
            devices_info_set, &current_device_info, SPDRP_UI_NUMBER);
        device_info.device_info = current_device_info;

        HKEY hkey =
            GetDeviceRegistryKey(devices_info_set, &current_device_info);
        if (hkey != INVALID_HANDLE_VALUE) {
          device_info.registry_pathname = GetRegistryPathFromHKEY(hkey);
          CloseHandle(hkey);
          if (!device_info.registry_pathname.empty()) {
            devices.push_back(device_info);
          } else {
            cout << "GVNICHELPER_ERROR: Failed to get device registry path "
                 << endl;
            return FALSE;
          }
        }
      }
    } else {
      cout << "GVNICHELPER_ERROR: CM_Get_Device_ID_Ex failed with error "
           << GetErrorMessage(return_value) << endl;
      return FALSE;
    }
  }

  DWORD error = GetLastError();
  if (error != ERROR_NO_MORE_ITEMS) {
    cout << "GVNICHELPER_ERROR: SetupDiEnumDeviceInfo failed with error "
         << GetErrorMessage(error) << endl;
    SetupDiDestroyDeviceInfoList(devices_info_set);
    return TRUE;
  }

  // Sorting the devices list to make sure they are in same order everytime.
  // The API functions may not enumerate the list in same order
  sort(devices.begin(), devices.end(), DevicesComparator);
  gvnic_devices_ = devices;

  return TRUE;
}

// Get devices information list of given guid class
// SetupDiGetClassDevsEx : returns a handle to a device information set that
// contains requested device information elements SetupDiGetDeviceInfoListDetail
// : retrieves information associated with a device information set
BOOL GvnicDevices::GetDevicesInfoList(
    GUID* device_class_guids, SP_DEVINFO_LIST_DETAIL_DATA* devices_info_list) {
  HDEVINFO devices_info_set;

  devices_info_set = SetupDiGetClassDevsEx(device_class_guids, NULL, NULL,
                                           DIGCF_PRESENT, NULL, NULL, NULL);

  if (devices_info_set == INVALID_HANDLE_VALUE) {
    DWORD error = GetLastError();
    cout << "GVNICHELPER_ERROR: SetupDiGetClassDevsEx failed with error "
         << GetErrorMessage(error) << endl;
    return FALSE;
  }

  devices_info_set_ = devices_info_set;

  if (!SetupDiGetDeviceInfoListDetail(devices_info_set, devices_info_list)) {
    DWORD error = GetLastError();
    cout << "GVNICHELPER_ERROR: SetupDiGetDeviceInfoListDetail "
            "failed with error "
         << GetErrorMessage(error) << endl;
    SetupDiDestroyDeviceInfoList(devices_info_set);
    return FALSE;
  }

  return TRUE;
}

// Get Network devices class guids
// SetupDiClassGuidsFromNameEx : Retrieves the GUIDs associated with specific
// class name
BOOL GvnicDevices::GetNetDeviceClassGuids(vector<GUID>& guids) {
  GUID* device_class_guids = NULL;
  DWORD num_guids;

  // First time we are passing null array and 0 as size.
  // The required size will be filled by the function in num_guids
  if (!SetupDiClassGuidsFromNameEx(kNetworkDevicesClass, NULL, 0, &num_guids,
                                   NULL, NULL)) {
    DWORD error = GetLastError();
    if (error == ERROR_INSUFFICIENT_BUFFER) {
      device_class_guids = new GUID[num_guids];
      if (!SetupDiClassGuidsFromNameEx(kNetworkDevicesClass, device_class_guids,
                                       num_guids, &num_guids, NULL, NULL)) {
        cout << "GVNICHELPER_ERROR: SetupDiClassGuidsFromNameEx "
                "failed with error "
             << GetErrorMessage(error) << endl;
        delete[] device_class_guids;
        return FALSE;
      }
    } else {
      cout
          << "GVNICHELPER_ERROR: SetupDiClassGuidsFromNameEx failed with error "
          << GetErrorMessage(error) << endl;
      return FALSE;
    }
  }

  guids.insert(guids.end(), &device_class_guids[0],
               &device_class_guids[num_guids]);
  delete[] device_class_guids;
  return TRUE;
}

BOOL GvnicDevices::Init() {
  vector<GUID> guids;
  GetNetDeviceClassGuids(guids);
  if (guids.empty()) {
    return FALSE;
  }
  SP_DEVINFO_LIST_DETAIL_DATA devices_info_list;
  devices_info_list.cbSize = sizeof(devices_info_list);

  if (GetDevicesInfoList(&guids[0], &devices_info_list)) {
    if (GetGvnicDevicesDetailInfo(devices_info_list)) {
      return TRUE;
    }
  }
  return FALSE;
}
