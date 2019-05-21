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

#ifndef REGISTRY_ACCESS_H_
#define REGISTRY_ACCESS_H_

#include <windows.h>

#include <iostream>
#include <vector>

using std::pair;
using std::string;
using std::vector;

constexpr DWORD kDefaultRegistryEntryLength = 256;
constexpr LPCTSTR kDeviceParamsSubkey = "Ndi\\Params";
constexpr LPCTSTR kRegistryPathDelimiter = "\\";
constexpr LPCTSTR kDefaultParameterName = "default";

class RegistryAccess {
 public:
  RegistryAccess(string registry_path);

  // Not copyable and movable
  RegistryAccess(const RegistryAccess&) = delete;
  RegistryAccess& operator=(const RegistryAccess&) = delete;

  BOOL ReadValue(string parameter_name, DWORD size, LPSTR parameter_value);
  BOOL ReadValue(string parameter_name, DWORD size, string subkey,
                 LPSTR parameter_value);
  BOOL WriteValue(LPCTSTR value_name, LPCTSTR value);
  BOOL DeleteValue(LPCTSTR value_name);
  // Gets all the parameter names of the device
  BOOL ReadParameterNames(vector<string>& parameter_names);
  // Gets all the values for the corresponding parameter names
  BOOL ReadParameterValues(vector<string> parameter_names,
                           vector<pair<string, string> >& parameter_values);
  BOOL ReadParameterValues(vector<string> parameter_names, string subkey,
                           vector<pair<string, string> >& parameter_values);

  // Gets all the enum numbers of the given parameter
  BOOL ReadEnumNames(string subkey, vector<string>& parameter_names);

 private:
  string registry_path_;
};

#endif  // REGISTRY_ACCESS_H_
