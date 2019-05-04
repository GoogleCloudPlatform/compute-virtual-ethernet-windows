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

// The ZwQueryKey routine provides information about the class of a registry
// key, and the number and sizes of its subkeys. ZwQueryKey is included in
// windows driver model. For user mode applications it can be accessed by
// loading ntdll library. ZwQueryKey function is used below to retrieve name
// information of the given registry key

#include "device_registry.h"  // NOLINT: include directory

#include <string>

#include "gvnic_helper.h"  // NOLINT: include directory

using std::cout;
using std::endl;
using std::wstring;

constexpr LPCTSTR kRegistryPrefix = "\\REGISTRY\\MACHINE\\";

typedef LONG NTSTATUS;

#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

wstring GetWstringRegistryPathFromHKEY(HKEY hkey) {
  // L is the prefix for wide character
  wstring registry_path(L"");

  if (hkey == NULL) {
    cout << "GVNICHELPER_ERROR : device hkey NULL" << endl;
    return registry_path;
  }

  HMODULE handle_ntdll = LoadLibrary("ntdll.dll");

  if (handle_ntdll == NULL) {
    cout << "GVNICHELPER_ERROR :  Unable to load ntdll library" << endl;
    return registry_path;
  }

  typedef DWORD(__stdcall * ZwQueryKeyType)(
      HANDLE KeyHandle, int KeyInformationClass, PVOID KeyInformation,
      ULONG Length, PULONG ResultLength);

  ZwQueryKeyType zw_query_key = reinterpret_cast<ZwQueryKeyType>(
      ::GetProcAddress(handle_ntdll, "ZwQueryKey"));

  if (zw_query_key == NULL) {
    cout << "GVNICHELPER_ERROR : Unable to get address of "
            "ZwQueryKey function"
         << endl;
    return registry_path;
  }

  DWORD size = 0;
  DWORD result = 0;

  // First pass size 0, the function see's the buffer is small
  // and fills the required size for path in size variable. size
  // returned is in bytes.
  // KeyInformationClass = 3 (KeyInformationName)
  result = zw_query_key(hkey, 3, 0, 0, &size);
  if (result == STATUS_BUFFER_TOO_SMALL) {
    wchar_t* path_name = new wchar_t[size / sizeof(wchar_t) + 1];
    result = zw_query_key(hkey, 3, path_name, size, &size);

    if (result == STATUS_SUCCESS) {
      // ZwQueryKey returns stream. It contains "L " at the beginning
      // which is generally used to indicate wchar to the compiler. While
      // storing it as a char array starting two bytes need to be removed
      path_name[size / sizeof(wchar_t)] = L'\0';
      registry_path = wstring(path_name + 2);
    } else {
      cout << "GVNICHELPER_ERROR : ZwQueryKey failed with error "
           << GetErrorMessage(result) << endl;
      return registry_path;
    }
    delete[] path_name;
  } else {
    cout << "GVNICHELPER_ERROR : ZwQueryKey failed with error "
         << GetErrorMessage(result) << endl;
    return registry_path;
  }

  FreeLibrary(handle_ntdll);
  return registry_path;
}

string WstringToString(const wstring& str) {
  string result("");
  size_t buffer_length = str.length() + 1;
  CHAR* buffer = new CHAR[buffer_length];

  if (buffer == NULL) {
    cout << "GVNICHELPER_ERROR: Failed to convert wstring to string" << endl;
    return result;
  }

  size_t count;
  DWORD return_value;
  // Converts a sequence of wide characters to a corresponding sequence
  // of multibyte characters
  return_value =
      wcstombs_s(&count, buffer, buffer_length, str.c_str(), buffer_length);
  if (return_value != 0) {
    cout << "GVNICHELPER_ERROR: wcstombs_s Failed with error "
         << GetErrorMessage(return_value) << endl;
    return result;
  }

  result = string(buffer);
  delete[] buffer;
  return result;
}

string GetRegistryPathFromHKEY(HKEY hkey) {
  string path = WstringToString((GetWstringRegistryPathFromHKEY(hkey)));
  if (path.substr(0, string(kRegistryPrefix).length()) == kRegistryPrefix) {
    return path.substr(string(kRegistryPrefix).length());
  } else {
    return string("");
  }
}
