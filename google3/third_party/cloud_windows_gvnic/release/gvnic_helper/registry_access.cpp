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

#include "registry_access.h"  // NOLINT: include directory

#include <tchar.h>

#include <iostream>
#include <string>

#include "gvnic_helper.h"  // NOLINT: include directory

using std::cout;
using std::endl;

static const HKEY kRegistryRoot = HKEY_LOCAL_MACHINE;

RegistryAccess::RegistryAccess(string registry_path) : registry_path_("") {
  registry_path_ = registry_path;
}

BOOL RegistryAccess::ReadValue(string parameter_name, DWORD size,
                               LPSTR parameter_value) {
  return ReadValue(parameter_name, size, "", parameter_value);
}

BOOL RegistryAccess::ReadValue(string parameter_name, DWORD size, string subkey,
                               LPSTR parameter_value) {
  HKEY hkey = NULL;
  string registry_path = registry_path_;
  if (subkey != "") {
    registry_path = registry_path + kRegistryPathDelimiter + subkey;
  }

  if (RegOpenKeyEx(kRegistryRoot, registry_path.c_str(), 0, KEY_QUERY_VALUE,
                   &hkey) != ERROR_SUCCESS) {
    cout << "GVNICHELPER_ERROR: RegOpenKeyEx failed with error: "
         << GetErrorMessage(GetLastError()) << endl;
    return FALSE;
  }

  DWORD registry_type = REG_SZ;
  if (RegQueryValueEx(hkey, parameter_name.c_str(), NULL, &registry_type,
                      (LPBYTE)parameter_value, &size) != ERROR_SUCCESS) {
    cout << "GVNICHELPER_ERROR: RegQueryKeyEx failed with error: "
         << GetErrorMessage(GetLastError()) << endl;
    RegCloseKey(hkey);
    return FALSE;
  }

  RegCloseKey(hkey);

  return TRUE;
}

BOOL RegistryAccess::WriteValue(LPCTSTR value_name, LPCTSTR value) {
  HKEY hkey = NULL;

  if (RegOpenKeyEx(kRegistryRoot, registry_path_.c_str(),
                   REG_OPTION_NON_VOLATILE, KEY_WRITE,
                   &hkey) != ERROR_SUCCESS) {
    cout << "GVNICHELPER_ERROR: RegOpenKeyEx failed with error: "
         << GetErrorMessage(GetLastError()) << endl;
    return FALSE;
  }

  // value_length must include the size of the terminating null character
  DWORD value_length = ((DWORD)_tcslen(value) + 1) * sizeof(value[0]);
  if (RegSetValueEx(hkey, value_name, 0, REG_SZ, (LPCBYTE)value,
                    value_length) != ERROR_SUCCESS) {
    cout << "GVNICHELPER_ERROR: RegSetValueEx failed with error: "
         << GetErrorMessage(GetLastError()) << endl;
    RegCloseKey(hkey);
    return FALSE;
  }

  RegCloseKey(hkey);

  return TRUE;
}

BOOL RegistryAccess::DeleteValue(LPCTSTR value_name) {
  HKEY hkey = NULL;

  if (RegOpenKeyEx(kRegistryRoot, registry_path_.c_str(), 0, KEY_WRITE,
                   &hkey) != ERROR_SUCCESS) {
    cout << "GVNICHELPER_ERROR: RegOpenKeyEx failed with error: "
         << GetErrorMessage(GetLastError()) << endl;
    return FALSE;
  }

  if (RegDeleteValue(hkey, value_name) != ERROR_SUCCESS) {
    cout << "GVNICHELPER_ERROR: RegDeleteValue failed with error: "
         << GetErrorMessage(GetLastError()) << endl;
    RegCloseKey(hkey);
    return FALSE;
  }

  RegCloseKey(hkey);

  return TRUE;
}

BOOL RegistryAccess::ReadParameterNames(vector<string>& parameter_names) {
  HKEY hkey = NULL;
  string params_registry_path =
      registry_path_ + kRegistryPathDelimiter + kDeviceParamsSubkey;

  if (RegOpenKeyEx(kRegistryRoot, params_registry_path.c_str(), 0,
                   KEY_ENUMERATE_SUB_KEYS, &hkey) != ERROR_SUCCESS) {
    cout << "GVNICHELPER_ERROR: RegOpenKeyEx failed with error: "
         << GetErrorMessage(GetLastError()) << endl;
    return FALSE;
  }

  DWORD index = 0;
  DWORD return_value = ERROR_NOT_FOUND;
  while (return_value != ERROR_NO_MORE_ITEMS) {
    CHAR key_name[kDefaultRegistryEntryLength];
    DWORD size = ARRAY_SIZE(key_name);
    return_value =
        RegEnumKeyEx(hkey, index, key_name, &size, NULL, NULL, NULL, NULL);
    if (return_value == ERROR_SUCCESS) {
      string key(key_name);
      parameter_names.push_back(key);
    } else if (return_value != ERROR_NO_MORE_ITEMS) {
      cout << "GVNICHELPER_ERROR: RegEnumKeyEx failed with error: "
           << GetErrorMessage(GetLastError()) << endl;
      RegCloseKey(hkey);
      return FALSE;
    }
    index++;
  }

  RegCloseKey(hkey);

  return TRUE;
}

BOOL RegistryAccess::ReadParameterValues(
    vector<string> parameter_names,
    vector<pair<string, string> >& parameter_values) {
  return ReadParameterValues(parameter_names, "", parameter_values);
}

BOOL RegistryAccess::ReadParameterValues(
    vector<string> parameter_names, string subkey,
    vector<pair<string, string> >& parameter_values) {
  HKEY hkey = NULL;
  string registry_path = registry_path_;
  if (subkey != "") {
    registry_path = registry_path + kRegistryPathDelimiter + subkey;
  }

  if (RegOpenKeyEx(kRegistryRoot, registry_path.c_str(), 0, KEY_QUERY_VALUE,
                   &hkey) != ERROR_SUCCESS) {
    cout << "GVNICHELPER_ERROR: RegOpenKeyEx failed with error: "
         << GetErrorMessage(GetLastError()) << endl;
    return FALSE;
  }

  for (int i = 0; i < parameter_names.size(); i++) {
    string parameter_name = parameter_names[i];
    CHAR parameter_value[kDefaultRegistryEntryLength];
    DWORD size = ARRAY_SIZE(parameter_value);
    DWORD registry_type = REG_SZ;

    if (RegQueryValueEx(hkey, parameter_name.c_str(), NULL, &registry_type,
                        (LPBYTE)parameter_value, &size) == ERROR_SUCCESS) {
      pair<string, string> parameter_pair =
          make_pair(parameter_name, parameter_value);
      parameter_values.push_back(parameter_pair);
    } else {
      // If current value not set Get the default value for the property
      string subkey = string(kDeviceParamsSubkey) +
                      string(kRegistryPathDelimiter) + parameter_name;

      if (ReadValue(kDefaultParameterName, ARRAY_SIZE(parameter_value), subkey,
                    parameter_value)) {
        pair<string, string> parameter_pair =
            make_pair(parameter_name, parameter_value);
        parameter_values.push_back(parameter_pair);
      } else {
        cout << "GVNICHELPER_ERROR: RegOueryValueEx failed with error: "
             << GetErrorMessage(GetLastError()) << endl;
        RegCloseKey(hkey);
        return FALSE;
      }
    }
  }

  RegCloseKey(hkey);

  return TRUE;
}

BOOL RegistryAccess::ReadEnumNames(string subkey,
                                   vector<string>& parameter_names) {
  string registry_path = registry_path_ + kRegistryPathDelimiter + subkey;
  HKEY hkey = NULL;

  if (RegOpenKeyEx(kRegistryRoot, registry_path.c_str(), 0, KEY_QUERY_VALUE,
                   &hkey) != ERROR_SUCCESS) {
    cout << "GVNICHELPER_ERROR: RegOpenKeyEx failed with error: "
         << GetErrorMessage(GetLastError()) << endl;
    return FALSE;
  }

  DWORD index = 0;
  DWORD return_value = ERROR_NOT_FOUND;
  while (return_value != ERROR_NO_MORE_ITEMS) {
    CHAR key_name[kDefaultRegistryEntryLength];
    DWORD size = ARRAY_SIZE(key_name);
    return_value =
        RegEnumValue(hkey, index, key_name, &size, NULL, NULL, NULL, NULL);
    if (return_value == ERROR_SUCCESS) {
      string key(key_name);
      parameter_names.push_back(key);
    } else if (return_value != ERROR_NO_MORE_ITEMS) {
      cout << "GVNICHELPER_ERROR: RegEnumValue failed with error: "
           << GetErrorMessage(GetLastError()) << endl;
      RegCloseKey(hkey);
      return FALSE;
    }
    index++;
  }

  RegCloseKey(hkey);

  return TRUE;
}
