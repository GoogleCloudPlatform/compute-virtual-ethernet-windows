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

#ifndef DEVICE_PARAMETERS_H_
#define DEVICE_PARAMETERS_H_

#include <Windows.h>

#include <iostream>
#include <string>
#include <vector>

using std::pair;
using std::string;
using std::vector;

constexpr LPCTSTR kMinParameterName = "min";
constexpr LPCTSTR KMaxParameterName = "max";
constexpr LPCTSTR kStepParameterName = "step";
constexpr LPCTSTR kDescParameterName = "ParamDesc";

enum ParameterType { TYPE_ENUM, TYPE_INT, TYPE_LONG, TYPE_EDIT, TYPE_UNKNOWN };

class DeviceParameters {
 public:
  VOID SetParameterValue(string parameter_value) {
    parameter_value_ = parameter_value;
  }

  // Gets all driver setting names for given device
  static BOOL GetParameterNames(string registry_path,
                                vector<string>& parameter_names);

  // Gets names and values for all settings of the driver
  static BOOL GetParameterNamesValues(
      string registry_path, vector<pair<string, string> >& parameter_values);

  // Gets details of the parameter
  static DeviceParameters* GetParameterDetails(int device_index,
                                               string parameter_name);
  static ParameterType GetParameterType(string registry_path,
                                        string parameter_name);

  // Resets Device parameter value to its default value
  static BOOL ResetDeviceParameter(string registry_path, string parameter_name);

  // Gets all the details of the parameter
  virtual BOOL Init() = 0;
  virtual VOID PrintParameterDetails() = 0;

  /* Displays the parameter value
   * All derived classes use common PrintParameterValue function
   * in base class, except the DeviceEnumParameters. All enum parameter
   * values should be converted to corresponding string value
   */
  virtual BOOL PrintParameterValue();

  // Validates the parameter value before setting
  virtual BOOL ValidateValue() = 0;

  // Sets the value of parameter
  BOOL SetValue();

  // checks if given string has only digits
  static BOOL OnlyDigits(const string s);

 protected:
  VOID SetParameterName(string parameter_name) {
    parameter_name_ = parameter_name;
  }

  VOID SetRegistryPath(string registry_path) { registry_path_ = registry_path; }

  string GetParameterName() { return parameter_name_; }

  string GetParameterValue() { return parameter_value_; }

  string GetRegistryPath() { return registry_path_; }

  // Gets the string value of the given parameter name
  BOOL GetStringParameterValue(string parameter_name, string& parameter_value);

 private:
  string parameter_name_;
  string parameter_value_;
  string registry_path_;
};

#endif  // DEVICE_PARAMETERS_H_
