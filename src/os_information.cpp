#include "os_information.h"  // NOLINT: include directory

#include <wdm.h>

#include "trace.h"  // NOLINT: include directory
#include "utils.h"  // NOLINT: include directory
// NO REORDER: This is a load bearing comment
#include "os_information.tmh"  // NOLINT: trace message header

#define OS_VERSION_INFO_REGISTRY_CHAR_COUNT OS_VERSION_INFO_STR_CHAR_COUNT / 2

NDIS_STATUS OsInformation::Initialize(NDIS_HANDLE miniport_handle) {
  PAGED_CODE();
  registry_updated_ = false;

  update_build_release_ = AllocateMemory<UINT8>(
      miniport_handle, OS_VERSION_INFO_REGISTRY_CHAR_COUNT);
  if (update_build_release_ == nullptr) {
    DEBUGP(GVNIC_ERROR,
           "[%s] ERROR: Memory allocation failed for update_build_release_.",
           __FUNCTION__);
    return NDIS_STATUS_RESOURCES;
  }

  edition_display_ = AllocateMemory<UINT8>(miniport_handle,
                                           OS_VERSION_INFO_REGISTRY_CHAR_COUNT);
  if (edition_display_ == nullptr) {
    DEBUGP(GVNIC_ERROR,
           "[%s] ERROR: Memory allocation failed for edition_display_.",
           __FUNCTION__);
    return NDIS_STATUS_RESOURCES;
  }

  // Read os version info from registry
  query_registry_table_ =
      AllocateMemory<RTL_QUERY_REGISTRY_TABLE>(miniport_handle, 7);
  if (query_registry_table_ == nullptr) {
    DEBUGP(GVNIC_ERROR,
           "[%s] ERROR: Memory allocation failed for query_registry_table.",
           __FUNCTION__);
    return NDIS_STATUS_RESOURCES;
  }

  NTSTATUS status = query_registry();
  if (status == STATUS_OBJECT_NAME_NOT_FOUND) {
    status = query_wdm();
    if (status != STATUS_SUCCESS) {
      return NDIS_STATUS_FAILURE;
    }
  }

  return status;
}

NTSTATUS OsInformation::query_registry() {
  ULONG UbrLong = 0;
  UNICODE_STRING buildNumberUnicode;
  WCHAR buildNumberBuffer[OS_VERSION_INFO_REGISTRY_CHAR_COUNT];
  RtlInitEmptyUnicodeString(&buildNumberUnicode, buildNumberBuffer,
                            sizeof(buildNumberBuffer));
  UNICODE_STRING displayNameUnicode;
  WCHAR displayNameBuffer[OS_VERSION_INFO_REGISTRY_CHAR_COUNT];
  RtlInitEmptyUnicodeString(&displayNameUnicode, displayNameBuffer,
                            sizeof(displayNameBuffer));
  UNICODE_STRING editionIdUnicode;
  WCHAR editionIdBuffer[OS_VERSION_INFO_REGISTRY_CHAR_COUNT];
  RtlInitEmptyUnicodeString(&editionIdUnicode, editionIdBuffer,
                            sizeof(editionIdBuffer));

  ANSI_STRING updateBuildReleaseAnsi;
  RtlInitEmptyAnsiString(&updateBuildReleaseAnsi, (PCHAR)update_build_release_,
                         OS_VERSION_INFO_REGISTRY_CHAR_COUNT);
  ANSI_STRING editionDisplayAnsi;
  RtlInitEmptyAnsiString(&editionDisplayAnsi, (PCHAR)edition_display_,
                         OS_VERSION_INFO_REGISTRY_CHAR_COUNT);

  // Major REG_DWORD
  query_registry_table_[0].QueryRoutine = NULL;
  query_registry_table_[0].Flags = RTL_QUERY_REGISTRY_DIRECT;
  query_registry_table_[0].Name = (PWSTR)L"CurrentMajorVersionNumber";
  query_registry_table_[0].EntryContext = &major_version_;
  query_registry_table_[0].DefaultType = REG_NONE;
  query_registry_table_[0].DefaultData = NULL;
  query_registry_table_[0].DefaultLength = 0;
  // Minor REG_DWORD
  query_registry_table_[1].QueryRoutine = NULL;
  query_registry_table_[1].Flags = RTL_QUERY_REGISTRY_DIRECT;
  query_registry_table_[1].Name = (PWSTR)L"CurrentMinorVersionNumber";
  query_registry_table_[1].EntryContext = &minor_version_;
  query_registry_table_[1].DefaultType = REG_NONE;
  query_registry_table_[1].DefaultData = NULL;
  query_registry_table_[1].DefaultLength = 0;
  // Build REG_SZ
  query_registry_table_[2].QueryRoutine = NULL;
  query_registry_table_[2].Flags =
      RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_NOEXPAND;
  query_registry_table_[2].Name = (PWSTR)L"CurrentBuildNumber";
  query_registry_table_[2].EntryContext = &buildNumberUnicode;
  query_registry_table_[2].DefaultType = REG_NONE;
  query_registry_table_[2].DefaultData = NULL;
  query_registry_table_[2].DefaultLength = 0;
  // UBR REG_DWORD
  query_registry_table_[3].QueryRoutine = NULL;
  query_registry_table_[3].Flags = RTL_QUERY_REGISTRY_DIRECT;
  query_registry_table_[3].Name = (PWSTR)L"UBR";
  query_registry_table_[3].EntryContext = &UbrLong;
  query_registry_table_[3].DefaultType = REG_NONE;
  query_registry_table_[3].DefaultData = NULL;
  query_registry_table_[3].DefaultLength = 0;
  // DisplayVersion REG_SZ
  query_registry_table_[4].QueryRoutine = NULL;
  query_registry_table_[4].Flags =
      RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_NOEXPAND;
  query_registry_table_[4].Name = (PWSTR)L"DisplayVersion";
  query_registry_table_[4].EntryContext = &displayNameUnicode;
  query_registry_table_[4].DefaultType = REG_NONE;
  query_registry_table_[4].DefaultData = NULL;
  query_registry_table_[4].DefaultLength = 0;
  // EditionId REG_SZ
  query_registry_table_[5].QueryRoutine = NULL;
  query_registry_table_[5].Flags =
      RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_NOEXPAND;
  query_registry_table_[5].Name = (PWSTR)L"EditionID";
  query_registry_table_[5].EntryContext = &editionIdUnicode;
  query_registry_table_[5].DefaultType = REG_NONE;
  query_registry_table_[5].DefaultData = NULL;
  query_registry_table_[5].DefaultLength = 0;
  // Termination
  query_registry_table_[6].QueryRoutine = NULL;
  query_registry_table_[6].Flags = 0;
  query_registry_table_[6].Name = NULL;
  query_registry_table_[6].EntryContext = NULL;
  query_registry_table_[6].DefaultType = REG_NONE;
  query_registry_table_[6].DefaultData = NULL;
  query_registry_table_[6].DefaultLength = 0;

  // Reading registry path SOFTWARE\Microsoft\Windows NT\CurrentVersion
  NTSTATUS registry_status = RtlQueryRegistryValues(
      RTL_REGISTRY_WINDOWS_NT, L"", query_registry_table_, NULL, NULL);

  if (registry_status != STATUS_SUCCESS) {
    DEBUGP(GVNIC_WARNING,
           "[%s] Unable to query Windows registry. Error code: %#10x",
           __FUNCTION__, registry_status);
    return registry_status;
  }

  // Convert build number
  RtlUnicodeStringToInteger(&buildNumberUnicode, 10,
                            reinterpret_cast<PULONG>(&sub_version_));

  // Convert UBR number
  UNICODE_STRING ubrUnicode;
  WCHAR ubrUnicodeBuffer[OS_VERSION_INFO_STR_CHAR_COUNT];
  RtlInitEmptyUnicodeString(&ubrUnicode, ubrUnicodeBuffer,
                            sizeof(ubrUnicodeBuffer));
  RtlIntegerToUnicodeString(UbrLong, 10, &ubrUnicode);
  RtlUnicodeStringToAnsiString(&updateBuildReleaseAnsi, &ubrUnicode, false);

  // Convert edition(display)
  UNICODE_STRING editionDisplayUnicode;
  WCHAR editionDisplayBuffer[OS_VERSION_INFO_STR_CHAR_COUNT];
  RtlInitEmptyUnicodeString(&editionDisplayUnicode, editionDisplayBuffer,
                            sizeof(editionDisplayBuffer));
  RtlAppendUnicodeStringToString(&editionDisplayUnicode, &editionIdUnicode);
  RtlAppendUnicodeToString(&editionDisplayUnicode, (PCWSTR)L"(");
  RtlAppendUnicodeStringToString(&editionDisplayUnicode, &displayNameUnicode);
  RtlAppendUnicodeToString(&editionDisplayUnicode, (PCWSTR)L")");
  RtlUnicodeStringToAnsiString(&editionDisplayAnsi, &editionDisplayUnicode,
                               false);

  registry_updated_ = true;

  UINT8* ubr;
  if (!update_build_release(&ubr)) {
    DEBUGP(GVNIC_ERROR, "Unable to query update build release");
  }
  UINT8* edition;
  if (!update_build_release(&edition)) {
    DEBUGP(GVNIC_ERROR, "Unable to query edition");
  }

  DEBUGP(GVNIC_INFO,
         "[%s] Queried version information from registry. Major: %u Minor: %u "
         "build: %u ubr: %s edition: %s",
         __FUNCTION__, major_version(), minor_version(), sub_version(),
         reinterpret_cast<CHAR*>(ubr), reinterpret_cast<CHAR*>(edition));

  return NDIS_STATUS_SUCCESS;
}

NTSTATUS OsInformation::query_wdm() {
  RTL_OSVERSIONINFOW version_info;
  version_info.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
  NTSTATUS status = RtlGetVersion(&version_info);
  if (status != STATUS_SUCCESS) {
    DEBUGP(GVNIC_ERROR, "[%s] Unable to query version info. Error code: %#10x",
           __FUNCTION__, status);
    return status;
  }

  major_version_ = version_info.dwMajorVersion;
  minor_version_ = version_info.dwMinorVersion;
  sub_version_ = version_info.dwBuildNumber;

  DEBUGP(GVNIC_INFO,
         "[%s] Queried version information from WDM. Major: %u Minor: %u "
         "build: %u",
         __FUNCTION__, major_version(), minor_version(), sub_version());

  return status;
}

NTSTATUS OsInformation::update_build_release(UINT8** update_build_release) {
  NTSTATUS status = STATUS_SUCCESS;
  if (!registry_updated_) {
    status = query_registry();
    if (status != STATUS_SUCCESS) {
      return status;
    }
  }

  *update_build_release = update_build_release_;
  return status;
}

NTSTATUS OsInformation::edition_display(UINT8** edition_display) {
  NTSTATUS status = STATUS_SUCCESS;
  if (!registry_updated_) {
    status = query_registry();
    if (status != STATUS_SUCCESS) {
      return status;
    }
  }

  *edition_display = edition_display_;
  return status;
}

void OsInformation::Release() {
  FreeMemory(update_build_release_);
  update_build_release_ = nullptr;
  FreeMemory(edition_display_);
  edition_display_ = nullptr;
  FreeMemory(query_registry_table_);
  query_registry_table_ = nullptr;
  major_version_ = 0;
  minor_version_ = 0;
  sub_version_ = 0;
}
