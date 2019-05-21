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

#ifndef TRACE_H_
#define TRACE_H_

//
// Debug support macros
// -----------------------------------------------------------------------------
//
// This macros define the control GUID and trace flag for WPP event tracing.
// It is required to correctly capture and decode the event log.
// To learn more, go to
// https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/tools-for-software-tracing
//
// To use WPP tracking, set WPP enabled to true in source property and include
// this header above corresponding tmh header.

#define WPP_CONTROL_GUIDS                                        \
  WPP_DEFINE_CONTROL_GUID(                                       \
      GvnicMiniGUID, (B52B9907, 7581, 46F1, 8F13, 402BB15CC16C), \
      WPP_DEFINE_BIT(GVNIC_ERROR)   /* bit  0 = 0x00000001 */    \
      WPP_DEFINE_BIT(GVNIC_WARNING) /* bit  1 = 0x00000002 */    \
      WPP_DEFINE_BIT(GVNIC_INFO)    /* bit  2 = 0x00000004 */    \
      WPP_DEFINE_BIT(GVNIC_VERBOSE) /* bit  3 = 0x00000008 */    \
  )

#endif  // TRACE_H_
