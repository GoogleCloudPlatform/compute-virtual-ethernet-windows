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

#ifndef GVNIC_HELPER_H_
#define GVNIC_HELPER_H_

#include <windows.h>

#include <string>

using std::string;

#define GVNICHELPER_API __declspec(dllexport)

#ifdef __cplusplus
extern "C" {
#endif

DWORD GVNICHELPER_API InitHelperDll(DWORD netsh_version, PVOID reserved);
DWORD GVNICHELPER_API RegisterGvnicNetshHelper();
DWORD GVNICHELPER_API UnregisterGvnicNetshHelper();

#ifdef __cplusplus
}
#endif

static HINSTANCE gvnic_hinstance = NULL;

string GetErrorMessage(DWORD error_id);

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

#endif  // GVNIC_HELPER_H_
