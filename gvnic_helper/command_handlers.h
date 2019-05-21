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

#ifndef COMMAND_HANDLERS_H_
#define COMMAND_HANDLERS_H_

// clang-format off
#include <windows.h>
#include <NetSh.h>
// clang-format on

#include "resource.h"  // NOLINT: include directory

constexpr LPCWSTR CMD_SHOW = L"show";
constexpr LPCWSTR CMD_DEVICE = L"device";
constexpr LPCWSTR CMD_DEVICES = L"devices";
constexpr LPCWSTR CMD_PARAMETERS = L"parameters";
constexpr LPCWSTR CMD_PARAMINFO = L"paraminfo";
constexpr LPCWSTR CMD_SETTING = L"setting";
constexpr LPCWSTR CMD_SETTINGS = L"settings";
constexpr LPCWSTR CMD_SET = L"set";
constexpr LPCWSTR CMD_RESTART = L"restart";
constexpr LPCWSTR CMD_RESET = L"reset";

#define HLP_SHOW SHOW_HLP_MSG
#define HLP_DEVICE DEVICE_HLP_MSG
#define HLP_DEVICE_EX DEVICE_HLP_TOKEN
#define HLP_DEVICES DEVICES_HLP_MSG
#define HLP_DEVICES_EX DEVICES_HLP_TOKEN
#define HLP_PARAMETERS PARAMETERS_HLP_MSG
#define HLP_PARAMETERS_EX PARAMETERS_HLP_TOKEN
#define HLP_PARAMINFO PARAMINFO_HLP_MSG
#define HLP_PARAMINFO_EX PARAMINFO_HLP_TOKEN
#define HLP_SETTING SETTING_HLP_MSG
#define HLP_SETTING_EX SETTING_HLP_TOKEN
#define HLP_SETTINGS SETTINGS_HLP_MSG
#define HLP_SETTINGS_EX SETTINGS_HLP_TOKEN
#define HLP_SET SET_HLP_MSG
#define HLP_SET_EX SET_HLP_TOKEN
#define HLP_RESTART RESTART_HLP_MSG
#define HLP_RESTART_EX RESTART_HLP_TOKEN
#define HLP_RESET RESET_HLP_MSG
#define HLP_RESET_EX RESET_HLP_TOKEN

DWORD ShowDeviceCmdHandler(LPCWSTR machine, PWCHAR* arguments,
                           DWORD current_index, DWORD arg_count, DWORD flags,
                           LPCVOID data, BOOL* done);

DWORD ShowDevicesCmdHandler(LPCWSTR machine, PWCHAR* arguments,
                            DWORD current_index, DWORD arg_count, DWORD flags,
                            LPCVOID data, BOOL* done);

DWORD ShowParametersCmdHandler(LPCWSTR machine, PWCHAR* arguments,
                               DWORD current_index, DWORD arg_count,
                               DWORD flags, LPCVOID data, BOOL* done);

DWORD ShowParameterInfoCmdHandler(LPCWSTR machine, PWCHAR* arguments,
                                  DWORD current_index, DWORD arg_count,
                                  DWORD flags, LPCVOID data, BOOL* done);

DWORD ShowSettingCmdHandler(LPCWSTR machine, PWCHAR* arguments,
                            DWORD current_index, DWORD arg_count, DWORD flags,
                            LPCVOID data, BOOL* done);

DWORD ShowSettingsCmdHandler(LPCWSTR machine, PWCHAR* arguments,
                             DWORD current_index, DWORD arg_count, DWORD flags,
                             LPCVOID data, BOOL* done);

DWORD DumpCmdHandler(IN LPCWSTR machine, LPWSTR* arguments, DWORD arg_count,
                     IN LPCVOID data);

DWORD RestartCmdHandler(LPCWSTR machine, PWCHAR* arguments, DWORD current_index,
                        DWORD arg_count, DWORD flags, LPCVOID data, BOOL* done);

DWORD SetCmdHandler(LPCWSTR machine, PWCHAR* arguments, DWORD current_index,
                    DWORD arg_count, DWORD flags, LPCVOID data, BOOL* done);

DWORD ResetCmdHandler(LPCWSTR machine, PWCHAR* arguments, DWORD current_index,
                      DWORD arg_count, DWORD flags, LPCVOID data, BOOL* done);

static CMD_ENTRY show_command_group[] = {
    CREATE_CMD_ENTRY_EX(DEVICE, ShowDeviceCmdHandler,
                        CMD_FLAG_PRIVATE | CMD_FLAG_LOCAL),
    CREATE_CMD_ENTRY_EX(DEVICES, ShowDevicesCmdHandler,
                        CMD_FLAG_PRIVATE | CMD_FLAG_LOCAL),
    CREATE_CMD_ENTRY_EX(PARAMETERS, ShowParametersCmdHandler,
                        CMD_FLAG_PRIVATE | CMD_FLAG_LOCAL),
    CREATE_CMD_ENTRY_EX(PARAMINFO, ShowParameterInfoCmdHandler,
                        CMD_FLAG_PRIVATE | CMD_FLAG_LOCAL),
    CREATE_CMD_ENTRY_EX(SETTING, ShowSettingCmdHandler,
                        CMD_FLAG_PRIVATE | CMD_FLAG_LOCAL),
    CREATE_CMD_ENTRY_EX(SETTINGS, ShowSettingsCmdHandler,
                        CMD_FLAG_PRIVATE | CMD_FLAG_LOCAL)};

static CMD_GROUP_ENTRY command_groups[] = {CREATE_CMD_GROUP_ENTRY_EX(
    SHOW, show_command_group, CMD_FLAG_PRIVATE | CMD_FLAG_LOCAL)};

static CMD_ENTRY top_commands[] = {
    CREATE_CMD_ENTRY_EX(SET, SetCmdHandler, CMD_FLAG_PRIVATE | CMD_FLAG_LOCAL),
    CREATE_CMD_ENTRY_EX(RESTART, RestartCmdHandler,
                        CMD_FLAG_PRIVATE | CMD_FLAG_LOCAL),
    CREATE_CMD_ENTRY_EX(RESET, ResetCmdHandler,
                        CMD_FLAG_PRIVATE | CMD_FLAG_LOCAL)};

#endif  // COMMAND_HANDLERS_H_
