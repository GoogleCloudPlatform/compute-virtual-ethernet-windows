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

#include "gvnic_helper.h"  // NOLINT: include directory

#include <NetSh.h>

#include <iostream>

using std::cout;
using std::endl;

#include "command_handlers.h"  // NOLINT: include directory
#include "registry_access.h"   // NOLINT: include directory

constexpr GUID kGvnicGuid = {0xd5a8d0d,
                             0x2b48,
                             0x47b4,
                             {0x8f, 0x08, 0x9d, 0xf3, 0x7e, 0x9f, 0xad, 0xe8}};
constexpr DWORD kGvnicHelperVersion = 1;
constexpr LPWSTR kGvnicHelperName = L"gVNIC";
constexpr LPCTSTR kNetshHelperRegistryPath = TEXT("SOFTWARE\\Microsoft\\NetSh");

// Returns the string format of given win32 error_id
string GetErrorMessage(DWORD error_id) {
  LPSTR buffer = nullptr;
  size_t size = FormatMessageA(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
          FORMAT_MESSAGE_IGNORE_INSERTS,
      NULL, error_id, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&buffer,
      0, NULL);

  std::string message(buffer, size);

  // Free the buffer.
  LocalFree(buffer);

  return message;
}

DWORD GVNICHELPER_API UnregisterGvnicNetshHelper() {
  RegistryAccess registry_access(kNetshHelperRegistryPath);
  registry_access.DeleteValue("gvnichelper");
  return ERROR_SUCCESS;
}

DWORD GetThisDLLPathName(LPTSTR dll_path_name, DWORD* dll_path_length) {
  DWORD path_length =
      GetModuleFileName(gvnic_hinstance, dll_path_name, *dll_path_length);
  DWORD error = GetLastError();
  if (error != ERROR_SUCCESS) {
    return error;
  } else if (path_length == *dll_path_length) {
    return ERROR_BUFFER_OVERFLOW;
  } else {
    return ERROR_SUCCESS;
  }
}

DWORD GVNICHELPER_API RegisterGvnicNetshHelper() {
  CHAR dll_path_name[MAX_PATH];
  DWORD dll_path_length = ARRAY_SIZE(dll_path_name);

  DWORD return_value = GetThisDLLPathName(dll_path_name, &dll_path_length);
  if (return_value != ERROR_SUCCESS) {
    cout << "GIVNICHELPER_ERROR: GetThisDLLPathName failed with code: "
         << GetErrorMessage(return_value) << endl;
    return return_value;
  }

  RegistryAccess registry_access(kNetshHelperRegistryPath);
  if (registry_access.WriteValue("gvnichelper", dll_path_name)) {
    cout << "GVNICHELPER_ERROR: Registry operation failed with code: "
         << GetErrorMessage(return_value) << endl;
    return return_value;
  }
  return ERROR_SUCCESS;
}

DWORD WINAPI StartHelper(CONST GUID* guid_parent, DWORD version) {
  UNREFERENCED_PARAMETER(guid_parent);
  UNREFERENCED_PARAMETER(version);

  NS_CONTEXT_ATTRIBUTES attributes;
  ZeroMemory(&attributes, sizeof(attributes));

  attributes.pwszContext = kGvnicHelperName;
  attributes.guidHelper = kGvnicGuid;
  attributes.dwVersion = kGvnicHelperVersion;
  attributes.dwFlags = CMD_FLAG_LOCAL;
  attributes.pfnCommitFn = NULL;
  attributes.pfnDumpFn = DumpCmdHandler;
  attributes.pfnConnectFn = NULL;
  attributes.ulNumTopCmds = ARRAY_SIZE(top_commands);
  attributes.pTopCmds = (CMD_ENTRY(*)[]) & top_commands;
  attributes.ulNumGroups = ARRAY_SIZE(command_groups);
  attributes.pCmdGroups = (CMD_GROUP_ENTRY(*)[]) & command_groups;

  return RegisterContext(&attributes);
}

DWORD GVNICHELPER_API InitHelperDll(DWORD netsh_version, PVOID reserved) {
  UNREFERENCED_PARAMETER(netsh_version);
  UNREFERENCED_PARAMETER(reserved);

  NS_HELPER_ATTRIBUTES attributes;

  ZeroMemory(&attributes, sizeof(attributes));
  attributes.guidHelper = kGvnicGuid;
  attributes.dwVersion = kGvnicHelperVersion;
  attributes.pfnStart = StartHelper;
  attributes.pfnStop = NULL;

  RegisterHelper(NULL, &attributes);

  return NO_ERROR;
}

BOOL GVNICHELPER_API DllMain(HINSTANCE dll_hinstance, DWORD reason,
                             LPVOID reserved) {
  UNREFERENCED_PARAMETER(reserved);
  if (DLL_PROCESS_ATTACH == reason) {
    gvnic_hinstance = dll_hinstance;
  }

  return TRUE;
}
