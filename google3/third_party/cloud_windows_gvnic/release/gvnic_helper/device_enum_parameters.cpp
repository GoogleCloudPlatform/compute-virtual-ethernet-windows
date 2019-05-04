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

#include "device_enum_parameters.h"  // NOLINT: include directory

#include "gvnic_helper.h"     // NOLINT: include directory
#include "registry_access.h"  // NOLINT: include directory

using std::cout;
using std::endl;

constexpr LPCTSTR kEnumParameterName = "Enum";

DeviceEnumParameters::DeviceEnumParameters(string parameter_name,
                                           string registry_path) {
  SetParameterName(parameter_name);
  SetRegistryPath(registry_path);
  SetParameterValue("");
}

BOOL DeviceEnumParameters::Init() {
  if (!GetEnumParameterValues()) return FALSE;

  string default_value = "";
  if (!GetStringParameterValue(kDefaultParameterName, default_value)) {
    return FALSE;
  }
  default_value_ = default_value;

  string default_enum_value = "";
  if (!GetEnumValue(default_value, default_enum_value)) {
    return FALSE;
  }
  default_value_ = default_enum_value;

  string description = "";
  GetStringParameterValue(kDescParameterName, description);
  description_ = description;

  return TRUE;
}

BOOL DeviceEnumParameters::GetEnumParameterValues() {
  vector<string> parameter_names;
  vector<pair<string, string> > parameter_values;
  string subkey = string(kDeviceParamsSubkey) + string(kRegistryPathDelimiter) +
                  GetParameterName() + string(kRegistryPathDelimiter) +
                  string(kEnumParameterName);
  RegistryAccess registry_access(GetRegistryPath());
  if (registry_access.ReadEnumNames(subkey, parameter_names)) {
    if (registry_access.ReadParameterValues(parameter_names, subkey,
                                            parameter_values)) {
      enum_values_ = parameter_values;
      return TRUE;
    }
  }
  return FALSE;
}

BOOL DeviceEnumParameters::GetEnumValue(string enum_num, string& enum_value) {
  pair<string, string> enum_pair;
  for (int i = 0; i < enum_values_.size(); i++) {
    enum_pair = enum_values_[i];
    if (enum_pair.first == enum_num) {
      enum_value = enum_pair.second;
      return TRUE;
    }
  }
  return FALSE;
}

VOID DeviceEnumParameters::PrintParameterDetails() {
  cout << "Parameter: " << GetParameterName() << endl;
  cout << "\tparameter_type  =  enum" << endl;
  pair<string, string> enum_pair;
  for (int i = 0; i < enum_values_.size(); i++) {
    enum_pair = enum_values_[i];
    cout << "\tvalue \"" << enum_pair.first << "\"  =  " << enum_pair.second
         << endl;
  }
  cout << "\tdefault  =  " << default_value_ << endl;
  cout << "\tdescription = " << description_ << endl;
  cout << endl;
}

BOOL DeviceEnumParameters::PrintParameterValue() {
  RegistryAccess registry_access(GetRegistryPath());
  string parameter_name = GetParameterName();
  CHAR parameter_value[kDefaultRegistryEntryLength];
  if (!registry_access.ReadValue(parameter_name, ARRAY_SIZE(parameter_value),
                                 parameter_value)) {
    return FALSE;
  }
  string enum_value = "";
  if (!GetEnumValue(string(parameter_value), enum_value)) {
    return FALSE;
  }
  cout << "\t" << parameter_name << "  =  " << parameter_value << " ("
       << enum_value << ") " << endl;
  return TRUE;
}

BOOL DeviceEnumParameters::ValidateValue() {
  BOOL result = FALSE;
  for (int i = 0; i < enum_values_.size(); i++) {
    if (enum_values_[i].first == GetParameterValue()) {
      result = TRUE;
      break;
    }
  }
  return result;
}
