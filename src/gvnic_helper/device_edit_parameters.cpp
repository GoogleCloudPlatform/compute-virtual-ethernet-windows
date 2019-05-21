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

#include "device_edit_parameters.h"  // NOLINT: include directory

using std::cout;
using std::endl;

constexpr LPCTSTR kEnumParameterName = "Enum";

DeviceEditParameters::DeviceEditParameters(string parameter_name,
                                           string registry_path) {
  SetParameterName(parameter_name);
  SetRegistryPath(registry_path);
  SetParameterValue("");
}

BOOL DeviceEditParameters::Init() {
  string description = "";
  GetStringParameterValue(kDescParameterName, description);
  description_ = description;
  return TRUE;
}

VOID DeviceEditParameters::PrintParameterDetails() {
  cout << "Parameter: " << GetParameterName() << endl;
  cout << "\tparameter_type  =  edit" << endl;
  cout << "\t\ttype  =  " << value_type_ << endl;
  cout << "\tdescription  =  " << description_ << endl;
  cout << endl;
}

// Edit parameter is a text - Any value can be entered
BOOL DeviceEditParameters::ValidateValue() { return TRUE; }
