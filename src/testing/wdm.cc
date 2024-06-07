#include "third_party/cloud_windows_gvnic/release/testing/wdm.h"

#include <codecvt>
#include <cstring>
#include <locale>
#include <string>

#include "third_party/cloud_windows_gvnic/release/testing/ndis-types.h"
#include "third_party/cloud_windows_gvnic/release/testing/ndis.h"
#include "third_party/cloud_windows_gvnic/release/testing/windows-types.h"

#define WIN_REGISTRY_MAJOR_VERSION_KEY L"CurrentMajorVersionNumber"
#define WIN_REGISTRY_MINOR_VERSION_KEY L"CurrentMinorVersionNumber"
#define WIN_REGISTRY_BUILD_VERSION_KEY L"CurrentBuildNumber"
#define WIN_REGISTRY_UBR_VERSION_KEY L"UBR"
#define WIN_REGISTRY_DISPLAY_VERSION_KEY L"DisplayVersion"
#define WIN_REGISTRY_EDITION_ID_KEY L"EditionID"

namespace {

void UnicodeStringAssignment(PUNICODE_STRING unicodeString,
                             const wchar_t *initialString) {
  wchar_t *buffer = reinterpret_cast<wchar_t *>(unicodeString->Buffer);
  wcscpy(buffer, initialString);
  unicodeString->Length = wcslen(buffer) * sizeof(WCHAR);
}

}  // namespace

namespace ndis_testing {

WdmStub *wdm_mock_object = nullptr;

PVOID WdmStub::ExAllocatePoolWithTag_impl(POOL_TYPE pool_type,
                                          SIZE_T number_of_bytes, ULONG tag) {
  return malloc(number_of_bytes);
}

void WdmStub::ExFreePoolWithTag_impl(PVOID p, ULONG tag) { free(p); }

PVOID WdmStub::IoAllocateErrorLogEntry_impl(PVOID io_object, UCHAR entry_size) {
  return malloc(entry_size);
}

void WdmStub::IoWriteErrorLogEntry_impl(PVOID el_entry) { free(el_entry); }

NTSTATUS WdmStub::RtlAppendUnicodeToString_impl(
    _In_ _Out_ PUNICODE_STRING Destination, _In_ _Optional_ PCWSTR Source) {
  wchar_t *buffer = reinterpret_cast<wchar_t *>(Destination->Buffer);
  const wchar_t *src = reinterpret_cast<const wchar_t *>(Source);
  size_t src_len = wcslen(Source) * sizeof(WCHAR);

  memcpy(buffer + (Destination->Length / sizeof(WCHAR)), src, src_len);
  Destination->Length = Destination->Length + src_len;

  return STATUS_SUCCESS;
}

NTSTATUS WdmStub::RtlAppendUnicodeStringToString_impl(
    _In_ _Out_ PUNICODE_STRING Destination, _In_ PCUNICODE_STRING Source) {
  if (Source->Length > Destination->MaximumLength - Destination->Length) {
    return STATUS_BUFFER_TOO_SMALL;
  }
  wchar_t *buffer = reinterpret_cast<wchar_t *>(Destination->Buffer);
  wchar_t *src = reinterpret_cast<wchar_t *>(Source->Buffer);

  memcpy(buffer + (Destination->Length / sizeof(WCHAR)), src, Source->Length);
  Destination->Length = Destination->Length + Source->Length;

  return STATUS_SUCCESS;
}

void WdmStub::RtlCopyMemory_impl(void *destination, const void *source,
                                 size_t length) {
  memcpy(destination, source, length);
}

NTSTATUS WdmStub::RtlGetVersion_impl(PRTL_OSVERSIONINFOW lpVersionInformation) {
  if (lpVersionInformation == NULL ||
      lpVersionInformation->dwOSVersionInfoSize != sizeof(RTL_OSVERSIONINFOW)) {
    return STATUS_INVALID_PARAMETER;
  }

  lpVersionInformation->dwMajorVersion = 10;
  lpVersionInformation->dwMinorVersion = 0;
  lpVersionInformation->dwBuildNumber = 1337;

  return STATUS_SUCCESS;
}

VOID WdmStub::RtlInitEmptyAnsiString_impl(_Out_ PANSI_STRING AnsiString,
                                          _In_ PCHAR Buffer,
                                          _In_ USHORT BufferSize) {
  memset(Buffer, '\0', BufferSize);
  AnsiString->Buffer = Buffer;
  AnsiString->Length = 0;
  AnsiString->MaximumLength = BufferSize;
}

VOID WdmStub::RtlInitEmptyUnicodeString_impl(
    _Out_ PUNICODE_STRING UnicodeString, _In_ PWCHAR Buffer,
    _In_ USHORT BufferSize) {
  wmemset(Buffer, L'\0', BufferSize / sizeof(WCHAR));
  UnicodeString->Buffer = Buffer;
  UnicodeString->Length = 0;
  UnicodeString->MaximumLength = BufferSize;
}

NTSTATUS WdmStub::RtlIntegerToUnicodeString_impl(ULONG value, ULONG base,
                                                 PUNICODE_STRING string) {
  if (base != 0 && base != 2 && base != 8 && base != 10 && base != 16) {
    return STATUS_INVALID_PARAMETER;
  }

  std::wstring s = std::to_wstring(value);
  string->Length = s.length() * sizeof(WCHAR);
  if (string->Length > string->MaximumLength) {
    return STATUS_BUFFER_OVERFLOW;
  }
  wchar_t *buffer = reinterpret_cast<wchar_t *>(string->Buffer);
  wcscpy(buffer, s.c_str());

  return STATUS_SUCCESS;
}

NTSTATUS WdmStub::RtlQueryRegistryValues_impl(
    _In_ ULONG RelativeTo, _In_ PCWSTR Path,
    _In_ _Out_ PRTL_QUERY_REGISTRY_TABLE QueryTable,
    _In_ _Optional_ PVOID Context, _In_ _Optional_ PVOID Environment) {
  // Incredilby simple mock of Registry reading logic

  PRTL_QUERY_REGISTRY_TABLE entry = QueryTable;
  int i = 0;
  while (i < 10) {  // Query limit to handle mistakenly untermed query tables
    if (entry->Name == NULL) {
      break;
    }
    std::wstring name = std::wstring((wchar_t *)entry->Name);
    if (name == WIN_REGISTRY_MAJOR_VERSION_KEY) {
      *((ULONG *)entry->EntryContext) = NTDDK_MOCK_WIN_MAJOR_VER;
    } else if (name == WIN_REGISTRY_MINOR_VERSION_KEY) {
      *((ULONG *)entry->EntryContext) = NTDDK_MOCK_WIN_MINOR_VER;
    } else if (name == WIN_REGISTRY_BUILD_VERSION_KEY) {
      UnicodeStringAssignment((PUNICODE_STRING)entry->EntryContext,
                              NTDDK_MOCK_WIN_BUILD_NUM);
    } else if (name == WIN_REGISTRY_UBR_VERSION_KEY) {
      *((ULONG *)entry->EntryContext) = NTDDK_MOCK_WIN_UBR_NUM;
    } else if (name == WIN_REGISTRY_DISPLAY_VERSION_KEY) {
      UnicodeStringAssignment((PUNICODE_STRING)entry->EntryContext,
                              NTDDK_MOCK_WIN_RELEASE_NAME);
    } else if (name == WIN_REGISTRY_EDITION_ID_KEY) {
      UnicodeStringAssignment((PUNICODE_STRING)entry->EntryContext,
                              NTDDK_MOCK_WIN_EDITION_ID);
    }
    entry++;
    i++;
  }

  if (i > 10) {
    return STATUS_NDIS_NOT_SUPPORTED;
  }

  return STATUS_SUCCESS;
}

NTSTATUS WdmStub::RtlUnicodeStringToAnsiString_impl(
    _In_ _Out_ PANSI_STRING DestinationString,
    _In_ PCUNICODE_STRING SourceString,
    _In_ BOOLEAN AllocateDestinationString) {
  const wchar_t *src = reinterpret_cast<const wchar_t *>(SourceString->Buffer);
  std::wstring srcWStr =
      std::wstring(src, 0, (SourceString->Length / sizeof(WCHAR)));
  std::string srcNStr = std::string(srcWStr.begin(), srcWStr.end());
  strcpy(DestinationString->Buffer,  // NOLINT: no absl wstring support
         srcNStr.c_str());
  return STATUS_SUCCESS;
}

NTSTATUS WdmStub::RtlUnicodeStringToInteger_impl(_In_ PCUNICODE_STRING String,
                                                 _In_ _Optional_ ULONG Base,
                                                 _Out_ PULONG Value) {
  const wchar_t *buffer = reinterpret_cast<const wchar_t *>(String->Buffer);
  *Value = std::wcstol(buffer, nullptr, Base);
  return STATUS_SUCCESS;
}

NTSTATUS WdmStub::RtlUnicodeToUTF8N_impl(PCHAR UTF8StringDestination,
                                         ULONG UTF8StringMaxByteCount,
                                         PULONG UTF8StringActualByteCount,
                                         PCWSTR UnicodeStringSource,
                                         ULONG UnicodeStringByteCount) {
  const wchar_t *src = reinterpret_cast<const wchar_t *>(UnicodeStringSource);
  std::wstring srcWStr =
      std::wstring(src, 0, (UnicodeStringByteCount / sizeof(WCHAR)));
  std::string srcNStr = std::string(srcWStr.begin(), srcWStr.end());
  strcpy(UTF8StringDestination,  // NOLINT: no absl wstring support
         srcNStr.c_str());
  return STATUS_SUCCESS;
}

void WdmStub::RtlZeroMemory_impl(PVOID destination, size_t length) {
  memset(destination, 0, length);
}

}  // namespace ndis_testing
