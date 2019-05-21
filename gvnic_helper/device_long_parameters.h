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

#ifndef DEVICE_LONG_PARAMETERS_H_
#define DEVICE_LONG_PARAMETERS_H_

#include "device_parameters.h"  // NOLINT: include directory

/* DeviceLongParameters handles the parameters whose value is a
 * long integer. Value has a lower limit, upper limit and an
 * increment value by which it can be changed and default value
 * Example : MTU
 *           min:576  max:6550  increment:1
 */

class DeviceLongParameters : public DeviceParameters {
 public:
  DeviceLongParameters(string parameter_name, string registry_path);

  // Not copyable and movable
  DeviceLongParameters(const DeviceLongParameters&) = delete;
  DeviceLongParameters& operator=(const DeviceLongParameters&) = delete;

  virtual BOOL Init();
  virtual VOID PrintParameterDetails();
  virtual BOOL ValidateValue();

 private:
  int64_t max_;
  int64_t min_;
  int64_t step_;
  int64_t default_value_;
  string description_;

  // Gets long value of the given parameter name
  BOOL GetLongParameterValue(string long_parameter, int64_t& value);
};

#endif  // DEVICE_LONG_PARAMETERS_H_
