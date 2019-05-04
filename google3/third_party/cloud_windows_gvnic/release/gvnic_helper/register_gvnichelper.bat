REM  Copyright 2019 Google LLC
REM
REM  Licensed under the Apache License, Version 2.0 (the "License");
REM  you may not use this file except in compliance with the License.
REM  You may obtain a copy of the License at
REM
REM       http://www.apache.org/licenses/LICENSE-2.0
REM
REM  Unless required by applicable law or agreed to in writing, software
REM  distributed under the License is distributed on an "AS IS" BASIS,
REM  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
REM  See the License for the specific language governing permissions and
REM  limitations under the License.

setlocal EnableDelayedExpansion

REM @echo off

REM To register or unregister gvnic helper in netsh registry
REM Usage:
REM To register : .\register_gvnichelper.bat register [PATH TO DLL]
REM To unregister : .\register_gvnichelper.bat unregister

set COMMAND=%1

if "!COMMAND!"=="register" goto register
if "!COMMAND!"=="unregister" goto unregister

:register
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NetSh" /v gvnichelper /t REG_SZ /d %2 /f
goto :eof

:unregister
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NetSh" /v gvnichelper /f
goto :eof
