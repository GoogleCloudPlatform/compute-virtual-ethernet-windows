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

#include "device_parameters.h"  // NOLINT: include directory

#include "device_edit_parameters.h"  // NOLINT: include directory
#include "device_enum_parameters.h"  // NOLINT: include directory
#include "device_int_parameters.h"   // NOLINT: include directory
#include "device_long_parameters.h"  // NOLINT: include directory
#include "gvnic_devices.h"           // NOLINT: include directory
#include "gvnic_helper.h"            // NOLINT: include directory
#include "registry_access.h"         // NOLINT: include directory

using std::cout;
using std::endl;

constexpr LPCTSTR kTypeParameterName = "type";

static const vector<string> kParameterTypes = {"enum", "int", "long", "edit"};

BOOL DeviceParameters::GetParameterNames(string registry_path,
                                         vector<string>& parameter_names) {
  RegistryAccess registry_access(registry_path);
  if (!registry_access.ReadParameterNames(parameter_names)) {
    return FALSE;
  }
  return TRUE;
}

BOOL DeviceParameters::GetParameterNamesValues(
    string registry_path, vector<pair<string, string> >& parameter_values) {
  vector<string> parameter_names;
  RegistryAccess registry_access(registry_path);

  if (registry_access.ReadParameterNames(parameter_names)) {
    if (registry_access.ReadParameterValues(parameter_names,
                                            parameter_values)) {
      return TRUE;
    }
  }
  return FALSE;
}

ParameterType DeviceParameters::GetParameterType(string registry_path,
                                                 string parameter_name) {
  ParameterType parameter_type = TYPE_UNKNOWN;
  string subkey = string(kDeviceParamsSubkey) + string(kRegistryPathDelimiter) +
                  parameter_name;
  RegistryAccess registry_access(registry_path);
  CHAR type_value[kDefaultRegistryEntryLength];

  if (registry_access.ReadValue(kTypeParameterName, ARRAY_SIZE(type_value),
                                subkey, type_value)) {
    string type = string(type_value);
    for (int i = 0; i < kParameterTypes.size(); i++) {
      if (type == kParameterTypes[i]) {
        parameter_type = (ParameterType)i;
        break;
      }
    }
  }
  return parameter_type;
}

DeviceParameters* DeviceParameters::GetParameterDetails(int device_index,
                                                        string parameter_name) {
  DeviceParameters* device_parameters = NULL;
  GvnicDevices gvnic_devices;
  if (!gvnic_devices.Init()) {
    return device_parameters;
  }
  vector<GvnicDeviceInfo> gvnic_device_list = gvnic_devices.GetGvnicDevices();
  string registry_path = gvnic_device_list[device_index].registry_pathname;
  ParameterType parameter_type =
      GetParameterType(registry_path, parameter_name);
  switch (parameter_type) {
    case TYPE_ENUM: {
      device_parameters =
          new DeviceEnumParameters(parameter_name, registry_path);
      break;
    }
    case TYPE_INT: {
      device_parameters =
          new DeviceIntParameters(parameter_name, registry_path);
      break;
    }
    case TYPE_LONG: {
      device_parameters =
          new DeviceLongParameters(parameter_name, registry_path);
      break;
    }
    case TYPE_EDIT: {
      device_parameters =
          new DeviceEditParameters(parameter_name, registry_path);
      break;
    }
    case TYPE_UNKNOWN: {
      break;
    }
  }

  /* If parameter value not among the above four types
   * ParameterType would be TYPE_UNKNOWN and device_parameters
   * would be NULL
   */
  if (device_parameters) {
    if (!device_parameters->Init()) {
      return NULL;
    }
  }

  return device_parameters;
}

BOOL DeviceParameters::GetStringParameterValue(string parameter_name,
                                               string& parameter_value) {
  string subkey = string(kDeviceParamsSubkey) + string(kRegistryPathDelimiter) +
                  GetParameterName();
  RegistryAccess registry_access(GetRegistryPath());
  CHAR string_value[kDefaultRegistryEntryLength];
  if (registry_access.ReadValue(parameter_name, ARRAY_SIZE(string_value),
                                subkey, string_value)) {
    parameter_value = string(string_value);
    return TRUE;
  }
  return FALSE;
}

BOOL DeviceParameters::PrintParameterValue() {
  RegistryAccess registry_access(registry_path_);
  CHAR parameter_value[kDefaultRegistryEntryLength];
  if (registry_access.ReadValue(parameter_name_, ARRAY_SIZE(parameter_value),
                                parameter_value)) {
    cout << "\t" << parameter_name_ << "  =  " << parameter_value << endl;
    return TRUE;
  }
  return FALSE;
}

BOOL DeviceParameters::SetValue() {
  RegistryAccess registry_access(registry_path_);
  if (registry_access.WriteValue(parameter_name_.c_str(),
                                 parameter_value_.c_str())) {
    return TRUE;
  }
  return FALSE;
}

BOOL DeviceParameters::ResetDeviceParameter(string registry_path,
                                            string parameter_name) {
  RegistryAccess registry_access(registry_path);
  CHAR default_value[kDefaultRegistryEntryLength];
  string subkey = string(kDeviceParamsSubkey) + string(kRegistryPathDelimiter) +
                  parameter_name;
  if (!registry_access.ReadValue(kDefaultParameterName,
                                 ARRAY_SIZE(default_value), subkey,
                                 default_value)) {
    return FALSE;
  }
  if (!registry_access.WriteValue(parameter_name.c_str(), default_value)) {
    return FALSE;
  }
  return TRUE;
}

BOOL DeviceParameters::OnlyDigits(const string s) {
  return (s.find_first_not_of("0123456789") == string::npos);
}
