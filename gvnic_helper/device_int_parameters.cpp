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

#include "device_int_parameters.h"  // NOLINT: include directory

#include "gvnic_helper.h"     // NOLINT: include directory
#include "registry_access.h"  // NOLINT: include directory

using std::cout;
using std::endl;
using std::stoi;

DeviceIntParameters::DeviceIntParameters(string parameter_name,
                                         string registry_path) {
  SetParameterName(parameter_name);
  SetRegistryPath(registry_path);
  SetParameterValue("");
}

BOOL DeviceIntParameters::Init() {
  int value = 0;
  if (!GetIntParameterValue(kMinParameterName, value)) {
    return FALSE;
  }
  min_ = value;

  if (!GetIntParameterValue(KMaxParameterName, value)) {
    return FALSE;
  }
  max_ = value;

  if (!GetIntParameterValue(kStepParameterName, value)) {
    return FALSE;
  }
  step_ = value;

  if (!GetIntParameterValue(kDefaultParameterName, value)) {
    return FALSE;
  }
  default_value_ = value;

  string description = "";
  GetStringParameterValue(kDescParameterName, description);
  description_ = description;

  return TRUE;
}

BOOL DeviceIntParameters::GetIntParameterValue(string int_parameter,
                                               int& value) {
  string subkey = string(kDeviceParamsSubkey) + string(kRegistryPathDelimiter) +
                  GetParameterName();
  RegistryAccess registry_access(GetRegistryPath());
  CHAR int_value[kDefaultRegistryEntryLength];
  if (registry_access.ReadValue(int_parameter, ARRAY_SIZE(int_value), subkey,
                                int_value)) {
    value = stoi(int_value);
    return TRUE;
  }
  return FALSE;
}

VOID DeviceIntParameters::PrintParameterDetails() {
  cout << "Parameter: " << GetParameterName() << endl;
  cout << "\tparameter_type  =  integer" << endl;
  cout << "\tmax_value  =  " << max_ << endl;
  cout << "\tmin_value  =  " << min_ << endl;
  cout << "\tincrement  =  " << step_ << endl;
  cout << "\tdefault  =  " << default_value_ << endl;
  cout << "\tdescription  =  " << description_ << endl;
  cout << endl;
}

BOOL DeviceIntParameters::ValidateValue() {
  string value = GetParameterValue();
  if (!DeviceParameters::OnlyDigits(value)) {
    return FALSE;
  }
  int int_value = stoi(value.c_str());  // NOLINT: Microsoft code
  if (int_value >= min_ && int_value <= max_) {
    if ((int_value - min_) % step_ == 0) {
      return TRUE;
    }
  }
  return FALSE;
}
