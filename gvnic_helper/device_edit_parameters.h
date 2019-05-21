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

#ifndef DEVICE_EDIT_PARAMETERS_H_
#define DEVICE_EDIT_PARAMETERS_H_

#include "device_parameters.h"  // NOLINT: include directory

/* DeviceEditeParameters handles the parameters whose value
 * is an editable Text value. It doesnt have any restrictions
 * on values.
 * Example: MAC Address
 */

class DeviceEditParameters : public DeviceParameters {
 public:
  DeviceEditParameters(string parameter_name, string registry_path);

  // Not copyable and movable
  DeviceEditParameters(const DeviceEditParameters&) = delete;
  DeviceEditParameters& operator=(const DeviceEditParameters&) = delete;

  virtual BOOL Init();
  virtual VOID PrintParameterDetails();
  virtual BOOL ValidateValue();

 private:
  string description_;
  const string value_type_ = "text";
};

#endif  // DEVICE_EDIT_PARAMETERS_H_
