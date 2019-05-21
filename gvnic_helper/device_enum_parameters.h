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

#ifndef DEVICE_ENUM_PARAMETERS_H_
#define DEVICE_ENUM_PARAMETERS_H_

#include "device_parameters.h"  // NOLINT: include directory

/* DeviceEnumParameters handles the parameters whose values
 * are of type enum. Each value has a list of corresponding
 * enum values.
 * Example: *LsoV2IPv4
 *          1 - Enabled   0 - Disabled
 */

class DeviceEnumParameters : public DeviceParameters {
 public:
  DeviceEnumParameters(string parameter_name, string registry_path);

  // Not copyable and movable
  DeviceEnumParameters(const DeviceEnumParameters&) = delete;
  DeviceEnumParameters& operator=(const DeviceEnumParameters&) = delete;

  virtual BOOL Init();
  virtual VOID PrintParameterDetails();

  // Prints the value of parameter. Prints
  // enum number and corresponding value.
  virtual BOOL PrintParameterValue();

  // Validates if the parameter value is
  // one of the enum_values
  virtual BOOL ValidateValue();

 private:
  // stores the enum number and corresponding value of
  // all enumerations for a parameter
  vector<pair<string, string> > enum_values_;
  string default_value_;
  string description_;

  // Gets all the enum values of the parameter
  BOOL GetEnumParameterValues();

  // Gets the enum value for the given enum number
  BOOL GetEnumValue(string enum_num, string& enum_value);
};

#endif
