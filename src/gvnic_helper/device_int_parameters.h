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

#ifndef DEVICE_INT_PARAMETERS_H_
#define DEVICE_INT_PARAMETERS_H_

#include "device_parameters.h"  // NOLINT: include directory

/* DeviceIntParameters handles the parameters whose value is
 * of type integer. It has an upper limit, lower limit and an
 * increment step by which the value can be changed and
 * default value
 */

class DeviceIntParameters : public DeviceParameters {
 public:
  DeviceIntParameters(string parameter_name, string registry_path);

  // Not copyable and movable
  DeviceIntParameters(const DeviceIntParameters&) = delete;
  DeviceIntParameters& operator=(const DeviceIntParameters&) = delete;

  virtual BOOL Init();
  virtual VOID PrintParameterDetails();
  virtual BOOL ValidateValue();

 private:
  int max_;
  int min_;
  int step_;
  int default_value_;
  string description_;

  // Gets integer value of given parameter name
  BOOL GetIntParameterValue(string int_parameter, int& value);
};

#endif  // DEVICE_INT_PARAMETERS_H_
