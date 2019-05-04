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

#include "command_handlers.h"  // NOLINT: include directory

#include <iostream>
#include <memory>
#include <sstream>
#include <string>

#include "device_parameters.h"  // NOLINT: include directory
#include "device_registry.h"    // NOLINT: include directory
#include "gvnic_devices.h"      // NOLINT: include directory
#include "gvnic_helper.h"       // NOLINT: include directory

using std::cout;
using std::endl;
using std::pair;
using std::unique_ptr;
using std::wstring;

namespace {

void PrintGvnicDeviceInfo(int device_index,
                          const GvnicDeviceInfo& gvnic_device_info) {
  cout << "Device: " << gvnic_device_info.device_instanceid << endl;
  cout << "\t Name: " << gvnic_device_info.device_name << endl;
  cout << "\t Index: " << device_index << endl;
  cout << "\t Description: " << gvnic_device_info.device_description << endl;
  cout << "\t Location: " << gvnic_device_info.location_info << endl;
  cout << "\t Number: " << gvnic_device_info.device_number << endl;
  cout << "\t Software Registry: " << gvnic_device_info.registry_pathname
       << endl;
}

DWORD GetDeviceInfo(wstring arg, int& device_index,
                    GvnicDeviceInfo& device_info) {
  if (!DeviceParameters::OnlyDigits(WstringToString(arg))) {
    return ERROR_INVALID_PARAMETER;
  }
  device_index = _wtoi(arg.c_str());

  GvnicDevices gvnic_devices;
  if (!gvnic_devices.Init()) {
    return ERROR_EXCEPTION_IN_SERVICE;
  }
  vector<GvnicDeviceInfo> gvnic_devices_list = gvnic_devices.GetGvnicDevices();
  if (device_index < 0 || device_index >= gvnic_devices_list.size()) {
    cout << "Invalid index. Check index value using 'show devices' command"
         << endl;
    return ERROR_INVALID_PARAMETER;
  }
  device_info = gvnic_devices_list[device_index];
  return NO_ERROR;
}

// Dispalys all parameter details of the given device
DWORD ShowParameterDetails(DWORD device_index, string registry_path) {
  vector<string> parameter_names;
  if (!DeviceParameters::GetParameterNames(registry_path, parameter_names)) {
    return ERROR_EXCEPTION_IN_SERVICE;
  }
  for (int i = 0; i < parameter_names.size(); i++) {
    DeviceParameters* device_parameters =
        DeviceParameters::GetParameterDetails(device_index, parameter_names[i]);
    if (device_parameters) {
      device_parameters->PrintParameterDetails();
    } else {
      /* If device_parameters is NULL, the parameter type is not
       * among the enum, int, long and edit type or some error occurred
       * while obtaining the parameter registry values
       */
      return ERROR_EXCEPTION_IN_SERVICE;
    }
  }
  return NO_ERROR;
}

// validate the parameter name given by user
DWORD CheckParameterName(string parameter_name, string registry_path) {
  vector<string> parameter_names;
  if (!DeviceParameters::GetParameterNames(registry_path, parameter_names)) {
    return ERROR_EXCEPTION_IN_SERVICE;
  }
  for (int i = 0; i < parameter_names.size(); i++) {
    if (parameter_names[i] == parameter_name) {
      return NO_ERROR;
    }
  }
  cout << "Invalid parameter name. Check parameter name using 'show "
          "parameters' command"
       << endl;
  return ERROR_INVALID_PARAMETER;
}

// Displays all the settings of a device
DWORD ShowSettings(string device_instanceid, string registry_path,
                   int device_index) {
  cout << "Device: " << device_instanceid << endl;
  cout << "Index:  " << device_index << endl;
  cout << "Settings: " << endl;
  vector<string> parameter_names;
  DWORD return_value =
      DeviceParameters::GetParameterNames(registry_path, parameter_names);

  for (int i = 0; i < parameter_names.size(); i++) {
    DeviceParameters* device_parameters =
        DeviceParameters::GetParameterDetails(device_index, parameter_names[i]);
    if (device_parameters == NULL) {
      return ERROR_EXCEPTION_IN_SERVICE;
    }
    if (!device_parameters->PrintParameterValue()) {
      return ERROR_EXCEPTION_IN_SERVICE;
    }
  }

  return NO_ERROR;
}

// Dumps the current configuration of device in form of script
DWORD DeviceDump(string registry_path, int device_index) {
  vector<pair<string, string> > parameter_values;
  if (!DeviceParameters::GetParameterNamesValues(registry_path,
                                                 parameter_values)) {
    return ERROR_EXCEPTION_IN_SERVICE;
  }
  vector<pair<string, string> >::iterator it;
  for (it = parameter_values.begin(); it != parameter_values.end(); it++) {
    cout << "set"
         << " index=" << device_index << " param=" << it->first
         << " value=" << it->second << endl;
  }
  cout << "restart " << device_index << endl;
  return NO_ERROR;
}

DWORD RestartDevice(DWORD device_index) {
  // Restart on a device cannot be done direclty.
  // It needs to be done through install params
  SP_PROPCHANGE_PARAMS params;
  params.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
  params.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
  params.StateChange = DICS_PROPCHANGE;
  params.Scope = DICS_FLAG_CONFIGSPECIFIC;
  params.HwProfile = 0;

  GvnicDevices gvnic_devices;
  if (!gvnic_devices.Init()) {
    return ERROR_EXCEPTION_IN_SERVICE;
  }
  HDEVINFO gvnic_devices_info = gvnic_devices.GetDevicesInfoSet();
  SP_DEVINFO_DATA gvnic_device_data =
      gvnic_devices.GetGvnicDevices()[device_index].device_info;

  // sets new install parameters of the device
  if (!SetupDiSetClassInstallParams(gvnic_devices_info, &gvnic_device_data,
                                    &params.ClassInstallHeader,
                                    sizeof(params))) {
    cout << "GVNICHELPER_ERROR: SetupDiSetClassInstallParams failed with error "
         << GetErrorMessage(GetLastError()) << endl;
    return ERROR_EXCEPTION_IN_SERVICE;
  }

  // Notifying that there is property change. System will restart the device.
  // If restart is not successfull, it will set DI_NEEDRESTART or DI_NEEDREBOOT
  // flag in SP_DEVINSTALL_PARAMS.
  if (!SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, gvnic_devices_info,
                                 &gvnic_device_data)) {
    DWORD error = GetLastError();
    cout << "GVNICHELPER_ERROR: SetupDiCallClassInstaller failed with error "
         << GetErrorMessage(error) << endl;
    if (error == ERROR_ACCESS_DENIED) {
      cout << "Admin rights required to run the command" << endl;
    }
    return ERROR_EXCEPTION_IN_SERVICE;
  }

  SP_DEVINSTALL_PARAMS device_install_params;
  device_install_params.cbSize = sizeof(SP_DEVINSTALL_PARAMS);

  // Get SP_DEVINSTALL_PARAMS  and check for flags
  if (!SetupDiGetDeviceInstallParams(gvnic_devices_info, &gvnic_device_data,
                                     &device_install_params)) {
    cout
        << "GVNICHELPER_ERROR: SetupDiGetDeviceInstallParams failed with error "
        << GetErrorMessage(GetLastError()) << endl;
    return ERROR_EXCEPTION_IN_SERVICE;
  }
  if (device_install_params.Flags & (DI_NEEDRESTART | DI_NEEDREBOOT)) {
    return ERROR_EXCEPTION_IN_SERVICE;
  }

  return NO_ERROR;
}

// resets all the parameters of the device to default values
BOOL ResetDevice(string registry_path) {
  vector<string> parameter_names;
  if (!DeviceParameters::GetParameterNames(registry_path, parameter_names)) {
    return FALSE;
  }
  for (int i = 0; i < parameter_names.size(); i++) {
    if (!DeviceParameters::ResetDeviceParameter(registry_path,
                                                parameter_names[i])) {
      return FALSE;
    }
  }
  return TRUE;
}

// Returns true if process is elevated
BOOL IsElevated() {
  HANDLE token = NULL;
  BOOL result = FALSE;
  if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
    TOKEN_ELEVATION elevation;
    DWORD size = sizeof(TOKEN_ELEVATION);
    if (GetTokenInformation(token, TokenElevation, &elevation,
                            sizeof(elevation), &size)) {
      result = elevation.TokenIsElevated;
    }
  }
  if (token) {
    CloseHandle(token);
  }
  return result;
}

}  // namespace

DWORD ShowDevicesCmdHandler(LPCWSTR machine, PWCHAR* arguments,
                            DWORD current_index, DWORD arg_count, DWORD flags,
                            LPCVOID data, BOOL* done) {
  // show devices
  // "netsh>gvnic> show devices" --> arg_count = 3
  if (arg_count != 3) {
    cout << "Invalid Syntax. Check Syntax using 'show devices ?' " << endl;
    return ERROR_INVALID_PARAMETER;
  }
  int i = 0;
  GvnicDevices gvnic_devices;
  if (!gvnic_devices.Init()) {
    return ERROR_EXCEPTION_IN_SERVICE;
  }
  vector<GvnicDeviceInfo> gvnic_devices_list = gvnic_devices.GetGvnicDevices();
  for (vector<GvnicDeviceInfo>::const_iterator it = gvnic_devices_list.begin();
       it != gvnic_devices_list.end(); it++) {
    PrintGvnicDeviceInfo(i, *it);
    i++;
  }
  return NO_ERROR;
}

DWORD ShowDeviceCmdHandler(LPCWSTR machine, PWCHAR* arguments,
                           DWORD current_index, DWORD arg_count, DWORD flags,
                           LPCVOID data, BOOL* done) {
  // show device [index=]0-N
  TAG_TYPE tags[] = {{L"index", NS_REQ_PRESENT}};
  unique_ptr<DWORD[]> tag_results(new DWORD[arg_count - current_index]);
  DWORD return_value;
  return_value = PreprocessCommand(NULL, arguments, current_index, arg_count,
                                   tags, ARRAY_SIZE(tags), ARRAY_SIZE(tags),
                                   ARRAY_SIZE(tags), tag_results.get());
  if (return_value != NO_ERROR) {
    return return_value;
  }

  int device_index;
  wstring arg = arguments[current_index + tag_results.get()[0]];
  GvnicDeviceInfo device_info;
  return_value = GetDeviceInfo(arg, device_index, device_info);
  if (return_value != NO_ERROR) {
    return return_value;
  }
  PrintGvnicDeviceInfo(device_index, device_info);
  return NO_ERROR;
}

DWORD ShowParametersCmdHandler(LPCWSTR machine, PWCHAR* arguments,
                               DWORD current_index, DWORD arg_count,
                               DWORD flags, LPCVOID data, BOOL* done) {
  // show parameters [index=]0-N
  TAG_TYPE tags[] = {{L"index", NS_REQ_PRESENT}};
  unique_ptr<DWORD[]> tag_results(new DWORD[arg_count - current_index]);
  DWORD return_value;
  return_value = PreprocessCommand(NULL, arguments, current_index, arg_count,
                                   tags, ARRAY_SIZE(tags), ARRAY_SIZE(tags),
                                   ARRAY_SIZE(tags), tag_results.get());
  if (return_value != NO_ERROR) {
    return return_value;
  }

  int device_index;
  wstring arg = arguments[current_index + tag_results.get()[0]];
  GvnicDeviceInfo device_info;
  return_value = GetDeviceInfo(arg, device_index, device_info);
  if (return_value != NO_ERROR) {
    return return_value;
  }

  vector<string> parameter_names;
  if (DeviceParameters::GetParameterNames(device_info.registry_pathname,
                                          parameter_names)) {
    cout << "Parameters:" << endl;
    for (int i = 0; i < parameter_names.size(); i++) {
      cout << "\t" << parameter_names[i] << endl;
    }
  } else {
    return ERROR_EXCEPTION_IN_SERVICE;
  }
  return NO_ERROR;
}

DWORD ShowParameterInfoCmdHandler(LPCWSTR machine, PWCHAR* arguments,
                                  DWORD current_index, DWORD arg_count,
                                  DWORD flags, LPCVOID data, BOOL* done) {
  // show paraminfo [index=]0-N [[param=]name]
  switch (arg_count) {
    case 4: {
      // show paraminfo 0
      TAG_TYPE tags[] = {{L"index", NS_REQ_PRESENT}};
      unique_ptr<DWORD[]> tag_results(new DWORD[arg_count - current_index]);
      DWORD preprocess_return = PreprocessCommand(
          NULL, arguments, current_index, arg_count, tags, ARRAY_SIZE(tags),
          ARRAY_SIZE(tags), ARRAY_SIZE(tags), tag_results.get());
      if (preprocess_return != NO_ERROR) {
        return preprocess_return;
      }

      DWORD return_value;
      int device_index;
      wstring arg = arguments[current_index + tag_results.get()[0]];
      GvnicDeviceInfo device_info;
      return_value = GetDeviceInfo(arg, device_index, device_info);
      if (return_value != NO_ERROR) {
        return return_value;
      }

      return_value =
          ShowParameterDetails(device_index, device_info.registry_pathname);
      if (return_value != NO_ERROR) {
        return return_value;
      }
      break;
    }
    case 5: {
      // show paraminfo 0 MTU
      TAG_TYPE tags[] = {{L"index", NS_REQ_PRESENT},
                         {L"param", NS_REQ_PRESENT}};
      unique_ptr<DWORD[]> tag_results(new DWORD[arg_count - current_index]);
      DWORD preprocess_return = PreprocessCommand(
          NULL, arguments, current_index, arg_count, tags, ARRAY_SIZE(tags),
          ARRAY_SIZE(tags), ARRAY_SIZE(tags), tag_results.get());
      if (preprocess_return != NO_ERROR) {
        return preprocess_return;
      }

      DWORD return_value;
      int device_index;
      wstring arg = arguments[current_index + tag_results.get()[0]];
      GvnicDeviceInfo device_info;
      return_value = GetDeviceInfo(arg, device_index, device_info);
      if (return_value != NO_ERROR) {
        return return_value;
      }

      wstring w_string = arguments[current_index + tag_results.get()[1]];
      string parameter_name = WstringToString(w_string);
      return_value =
          CheckParameterName(parameter_name, device_info.registry_pathname);
      if (return_value != NO_ERROR) {
        return return_value;
      }

      DeviceParameters* device_parameters =
          DeviceParameters::GetParameterDetails(device_index, parameter_name);
      if (device_parameters) {
        device_parameters->PrintParameterDetails();
      } else {
        return ERROR_EXCEPTION_IN_SERVICE;
      }
      break;
    }
    default: {
      cout << "The syntax supplied for this command is not valid. Check help "
              "for the correct syntax."
           << endl;
      cout << "show paraminfo [index=]0-N [[param=]name]" << endl;
    }
  }
  return NO_ERROR;
}

DWORD ShowSettingCmdHandler(LPCWSTR machine, PWCHAR* arguments,
                            DWORD current_index, DWORD arg_count, DWORD flags,
                            LPCVOID data, BOOL* done) {
  // show setting [index=]0-N [param=]name
  TAG_TYPE tags[] = {{L"index", NS_REQ_PRESENT}, {L"param", NS_REQ_PRESENT}};
  unique_ptr<DWORD[]> tag_results(new DWORD[arg_count - current_index]);
  DWORD preprocess_return = PreprocessCommand(
      NULL, arguments, current_index, arg_count, tags, ARRAY_SIZE(tags),
      ARRAY_SIZE(tags), ARRAY_SIZE(tags), tag_results.get());
  if (preprocess_return != NO_ERROR) {
    return preprocess_return;
  }

  DWORD return_value;
  int device_index;
  wstring arg = arguments[current_index + tag_results.get()[0]];
  GvnicDeviceInfo device_info;
  return_value = GetDeviceInfo(arg, device_index, device_info);
  if (return_value != NO_ERROR) {
    return return_value;
  }

  wstring w_string = arguments[current_index + tag_results.get()[1]];
  string parameter_name = WstringToString(w_string);
  return_value =
      CheckParameterName(parameter_name, device_info.registry_pathname);
  if (return_value != NO_ERROR) {
    return return_value;
  }

  DeviceParameters* device_parameters =
      DeviceParameters::GetParameterDetails(device_index, parameter_name);
  if (device_parameters == NULL) {
    return ERROR_EXCEPTION_IN_SERVICE;
  }
  if (!device_parameters->PrintParameterValue()) {
    return ERROR_EXCEPTION_IN_SERVICE;
  }

  return NO_ERROR;
}

// Displays all the settings of a device or of all devices
DWORD ShowSettingsCmdHandler(LPCWSTR machine, PWCHAR* arguments,
                             DWORD current_index, DWORD arg_count, DWORD flags,
                             LPCVOID data, BOOL* done) {
  // show settings [[index=]0-N]
  switch (arg_count) {
    case 3: {
      // show settings
      GvnicDevices gvnic_devices;
      if (!gvnic_devices.Init()) {
        return ERROR_EXCEPTION_IN_SERVICE;
      }
      vector<GvnicDeviceInfo> gvnic_device_list =
          gvnic_devices.GetGvnicDevices();

      DWORD return_value;
      for (int i = 0; i < gvnic_device_list.size(); i++) {
        return_value = ShowSettings(gvnic_device_list[i].device_instanceid,
                                    gvnic_device_list[i].registry_pathname, i);
        if (return_value != NO_ERROR) {
          return return_value;
        }
      }
      break;
    }
    case 4: {
      // show settings 0
      TAG_TYPE tags[] = {{L"index", NS_REQ_PRESENT}};
      unique_ptr<DWORD[]> tag_results(new DWORD[arg_count - current_index]);
      DWORD preprocess_return = PreprocessCommand(
          NULL, arguments, current_index, arg_count, tags, ARRAY_SIZE(tags),
          ARRAY_SIZE(tags), ARRAY_SIZE(tags), tag_results.get());
      if (preprocess_return != NO_ERROR) {
        return preprocess_return;
      }

      DWORD return_value;
      int device_index;
      wstring arg = arguments[current_index + tag_results.get()[0]];
      GvnicDeviceInfo device_info;
      return_value = GetDeviceInfo(arg, device_index, device_info);
      if (return_value != NO_ERROR) {
        return return_value;
      }

      return_value = ShowSettings(device_info.device_instanceid,
                                  device_info.registry_pathname, device_index);
      if (return_value != NO_ERROR) {
        return return_value;
      }
      break;
    }
    default: {
      cout << "The syntax supplied for this command is not valid. "
              "Check help for the correct syntax"
           << endl;
      cout << "show settings [[index=]0-N]" << endl;
      break;
    }
  }
  return NO_ERROR;
}

// Dumps the configuration of a device or of all devices
// in the form of script
DWORD DumpCmdHandler(IN LPCWSTR machine, LPWSTR* arguments, DWORD arg_count,
                     IN LPCVOID data) {
  // dump [[index=]0-N]
  switch (arg_count) {
    case 2: {
      // dump
      GvnicDevices gvnic_devices;
      if (!gvnic_devices.Init()) {
        return ERROR_EXCEPTION_IN_SERVICE;
      }

      DWORD return_value;
      vector<GvnicDeviceInfo> gvnic_device_list =
          gvnic_devices.GetGvnicDevices();
      cout << "\npushd gvnic\n" << endl;
      for (int i = 0; i < gvnic_device_list.size(); i++) {
        return_value = DeviceDump(gvnic_device_list[i].registry_pathname, i);
        if (return_value != NO_ERROR) {
          return return_value;
        }
      }
      cout << "\npopd gvnic\n" << endl;
      break;
    }
    case 3: {
      // dump 0
      DWORD return_value;
      int device_index;
      wstring arg = arguments[2];
      GvnicDeviceInfo device_info;
      return_value = GetDeviceInfo(arg, device_index, device_info);
      if (return_value != NO_ERROR) {
        return return_value;
      }
      cout << "\npushd gvnic\n" << endl;
      return_value = DeviceDump(device_info.registry_pathname, device_index);
      if (return_value != NO_ERROR) {
        return return_value;
      }
      cout << "\npopd gvnic\n" << endl;
      break;
    }
    default: {
      cout << "The syntax supplied for this command is not valid. "
              "Check help for the correct syntax"
           << endl;
      cout << "dump [[index=]0-N]" << endl;
      break;
    }
  }
  return NO_ERROR;
}

DWORD RestartCmdHandler(LPCWSTR machine, PWCHAR* arguments, DWORD current_index,
                        DWORD arg_count, DWORD flags, LPCVOID data,
                        BOOL* done) {
  // Restart [index=]0-N
  TAG_TYPE tags[] = {{L"index", NS_REQ_PRESENT}};
  unique_ptr<DWORD[]> tag_results(new DWORD[arg_count - current_index]);
  DWORD preprocess_return = PreprocessCommand(
      NULL, arguments, current_index, arg_count, tags, ARRAY_SIZE(tags),
      ARRAY_SIZE(tags), ARRAY_SIZE(tags), tag_results.get());
  if (preprocess_return != NO_ERROR) {
    return preprocess_return;
  }

  DWORD return_value;
  int device_index;
  wstring arg = arguments[current_index + tag_results.get()[0]];
  GvnicDeviceInfo device_info;
  return_value = GetDeviceInfo(arg, device_index, device_info);
  if (return_value != NO_ERROR) {
    return return_value;
  }

  if (!IsElevated()) {
    cout << "Admin rights are required for this command" << endl;
    return ERROR_EXCEPTION_IN_SERVICE;
  }
  return_value = RestartDevice(device_index);
  if (return_value != NO_ERROR) {
    cout << "Device Restart Failed" << endl;
    return ERROR_EXCEPTION_IN_SERVICE;
  }
  cout << "ok" << endl;
  return NO_ERROR;
}

DWORD SetCmdHandler(LPCWSTR machine, PWCHAR* arguments, DWORD current_index,
                    DWORD arg_count, DWORD flags, LPCVOID data, BOOL* done) {
  // set [index=]0-N [param=]name [value=]value
  TAG_TYPE tags[] = {
      {L"index", NS_REQ_PRESENT},
      {L"param", NS_REQ_PRESENT},
      {L"value", NS_REQ_PRESENT},
  };
  unique_ptr<DWORD[]> tag_results(new DWORD[arg_count - current_index]);
  DWORD preprocess_return = PreprocessCommand(
      NULL, arguments, current_index, arg_count, tags, ARRAY_SIZE(tags),
      ARRAY_SIZE(tags), ARRAY_SIZE(tags), tag_results.get());
  if (preprocess_return != NO_ERROR) {
    return preprocess_return;
  }

  DWORD return_value;
  int device_index;
  wstring arg = arguments[current_index + tag_results.get()[0]];
  GvnicDeviceInfo device_info;
  return_value = GetDeviceInfo(arg, device_index, device_info);
  if (return_value != NO_ERROR) {
    return return_value;
  }

  wstring w_string = L"";
  w_string = arguments[current_index + tag_results.get()[1]];
  string parameter_name = WstringToString(w_string);
  return_value =
      CheckParameterName(parameter_name, device_info.registry_pathname);
  if (return_value != NO_ERROR) {
    return return_value;
  }

  if (!IsElevated()) {
    cout << "Admin rights are required for this command" << endl;
    return ERROR_EXCEPTION_IN_SERVICE;
  }

  DeviceParameters* device_parameters =
      DeviceParameters::GetParameterDetails(device_index, parameter_name);
  if (device_parameters == NULL) {
    return ERROR_EXCEPTION_IN_SERVICE;
  }

  w_string = arguments[current_index + tag_results.get()[2]];
  string parameter_value = WstringToString(w_string);
  device_parameters->SetParameterValue(parameter_value);
  if (!device_parameters->ValidateValue()) {
    cout << "Invalid parameter value. Check valid values for the "
            "parameter using 'show paraminfo' command"
         << endl;
    return ERROR_INVALID_PARAMETER;
  }

  if (!device_parameters->SetValue()) {
    return ERROR_EXCEPTION_IN_SERVICE;
  }

  cout << "ok" << endl;
  return NO_ERROR;
}

DWORD ResetCmdHandler(LPCWSTR machine, PWCHAR* arguments, DWORD current_index,
                      DWORD arg_count, DWORD flags, LPCVOID data, BOOL* done) {
  // reset [index=]0-N [[param=]name]
  switch (arg_count) {
    case 3: {
      // reset 0
      TAG_TYPE tags[] = {{L"index", NS_REQ_PRESENT}};
      unique_ptr<DWORD[]> tag_results(new DWORD[arg_count - current_index]);
      DWORD preprocess_return = PreprocessCommand(
          NULL, arguments, current_index, arg_count, tags, ARRAY_SIZE(tags),
          ARRAY_SIZE(tags), ARRAY_SIZE(tags), tag_results.get());
      if (preprocess_return != NO_ERROR) {
        return preprocess_return;
      }

      DWORD return_value;
      int device_index;
      wstring arg = arguments[current_index + tag_results.get()[0]];
      GvnicDeviceInfo device_info;
      return_value = GetDeviceInfo(arg, device_index, device_info);
      if (return_value != NO_ERROR) {
        return return_value;
      }

      if (!IsElevated()) {
        cout << "Admin rights are required for this command" << endl;
        return ERROR_EXCEPTION_IN_SERVICE;
      }

      if (!ResetDevice(device_info.registry_pathname)) {
        return ERROR_EXCEPTION_IN_SERVICE;
      }
      return_value = RestartDevice(device_index);
      if (return_value != NO_ERROR) {
        return ERROR_SUCCESS_REBOOT_REQUIRED;
      }
      cout << "ok" << endl;
      break;
    }
    case 4: {
      // reset 0 MTU
      TAG_TYPE tags[] = {{L"index", NS_REQ_PRESENT},
                         {L"param", NS_REQ_PRESENT}};
      unique_ptr<DWORD[]> tag_results(new DWORD[arg_count - current_index]);
      DWORD preprocess_return = PreprocessCommand(
          NULL, arguments, current_index, arg_count, tags, ARRAY_SIZE(tags),
          ARRAY_SIZE(tags), ARRAY_SIZE(tags), tag_results.get());
      if (preprocess_return != NO_ERROR) {
        return preprocess_return;
      }

      DWORD return_value;
      int device_index;
      wstring arg = arguments[current_index + tag_results.get()[0]];
      GvnicDeviceInfo device_info;
      return_value = GetDeviceInfo(arg, device_index, device_info);
      if (return_value != NO_ERROR) {
        return return_value;
      }

      wstring w_string = arguments[current_index + tag_results.get()[1]];
      string parameter_name = WstringToString(w_string);
      return_value =
          CheckParameterName(parameter_name, device_info.registry_pathname);
      if (return_value != NO_ERROR) {
        return return_value;
      }

      if (!IsElevated()) {
        cout << "Admin rights are required for this command" << endl;
        return ERROR_EXCEPTION_IN_SERVICE;
      }

      if (!DeviceParameters::ResetDeviceParameter(device_info.registry_pathname,
                                                  parameter_name)) {
        return ERROR_EXCEPTION_IN_SERVICE;
      }
      return_value = RestartDevice(device_index);
      if (return_value != NO_ERROR) {
        return ERROR_SUCCESS_REBOOT_REQUIRED;
      }
      cout << "ok" << endl;
      break;
    }
    default: {
      cout << "The syntax supplied for this command is not valid. Check help "
              "for the correct syntax."
           << endl;
      cout << "reset [index=]0-N [[param=]name]" << endl;
    }
  }
  return NO_ERROR;
}
