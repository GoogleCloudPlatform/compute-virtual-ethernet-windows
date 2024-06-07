#ifndef THIRD_PARTY_CLOUD_WINDOWS_GVNIC_RELEASE_TESTING_WDM_H_
#define THIRD_PARTY_CLOUD_WINDOWS_GVNIC_RELEASE_TESTING_WDM_H_

#include "third_party/cloud_windows_gvnic/release/testing/wdm-types.h"
#include "third_party/cloud_windows_gvnic/release/testing/windows-types.h"

#define _Function_class_(x)
#define _In_
#define _Out_
#define _Optional_

#define NTDDK_MOCK_WIN_MAJOR_VER 5UL
#define NTDDK_MOCK_WIN_MINOR_VER 2UL
#define NTDDK_MOCK_WIN_BUILD_NUM L"987"
#define NTDDK_MOCK_WIN_BUILD_NUM_LONG 987UL
#define NTDDK_MOCK_WIN_UBR_NUM 543UL
#define NTDDK_MOCK_WIN_UBR_NUM_STR "543"
#define NTDDK_MOCK_WIN_RELEASE_NAME L"76H3"
#define NTDDK_MOCK_WIN_EDITION_ID L"TestingEnt"
#define NTDDK_MOCK_WIN_EDITION_DISPLAY "TestingEnt(76H3)"

namespace ndis_testing {

// For sanity, keep this header alpha sorted.
class WdmStub {
 public:
  WdmStub() {}
  virtual ~WdmStub() {}

  virtual PVOID ExAllocatePoolWithTag_impl(POOL_TYPE pool_type,
                                           SIZE_T number_of_bytes, ULONG tag);

  virtual void ExFreePoolWithTag_impl(PVOID p, ULONG tag);

  virtual PVOID IoAllocateErrorLogEntry_impl(PVOID io_object, UCHAR entry_size);

  virtual void IoWriteErrorLogEntry_impl(PVOID el_entry);

  virtual NTSTATUS RtlAppendUnicodeToString_impl(
      _In_ _Out_ PUNICODE_STRING Destination, _In_ _Optional_ PCWSTR Source);

  virtual NTSTATUS RtlAppendUnicodeStringToString_impl(
      PUNICODE_STRING destination, PUNICODE_STRING source);

  virtual void RtlCopyMemory_impl(void* destination, const void* source,
                                  size_t length);

  virtual NTSTATUS RtlGetVersion_impl(PRTL_OSVERSIONINFOW lpVersionInformation);

  virtual void RtlInitEmptyAnsiString_impl(_Out_ PANSI_STRING AnsiString,
                                           _In_ PCHAR Buffer,
                                           _In_ USHORT BufferSize);

  virtual VOID RtlInitEmptyUnicodeString_impl(
      _Out_ PUNICODE_STRING UnicodeString, _In_ PWCHAR Buffer,
      _In_ USHORT BufferSize);

  virtual NTSTATUS RtlIntegerToUnicodeString_impl(ULONG value, ULONG base,
                                                  PUNICODE_STRING string);

  virtual NTSTATUS RtlQueryRegistryValues_impl(
      _In_ ULONG RelativeTo, _In_ PCWSTR Path,
      _In_ _Out_ PRTL_QUERY_REGISTRY_TABLE QueryTable,
      _In_ _Optional_ PVOID Context, _In_ _Optional_ PVOID Environment);

  virtual NTSTATUS RtlUnicodeStringToAnsiString_impl(
      _In_ _Out_ PANSI_STRING DestinationString,
      _In_ PCUNICODE_STRING SourceString,
      _In_ BOOLEAN AllocateDestinationString);

  virtual NTSTATUS RtlUnicodeStringToInteger_impl(_In_ PCUNICODE_STRING String,
                                                  _In_ _Optional_ ULONG Base,
                                                  _Out_ PULONG Value);

  virtual NTSTATUS RtlUnicodeToUTF8N_impl(
      _Out_ PCHAR UTF8StringDestination, _In_ ULONG UTF8StringMaxByteCount,
      _Out_ PULONG UTF8StringActualByteCount, _In_ PCWSTR UnicodeStringSource,
      _In_ ULONG UnicodeStringByteCount);

  virtual void RtlZeroMemory_impl(PVOID destination, size_t length);
};

extern WdmStub* wdm_mock_object;

}  // namespace ndis_testing

#define ExAllocatePoolWithTag(...) \
  ndis_testing::wdm_mock_object->ExAllocatePoolWithTag_impl(__VA_ARGS__)

#define ExFreePoolWithTag(...) \
  ndis_testing::wdm_mock_object->ExFreePoolWithTag_impl(__VA_ARGS__)

#define IoAllocateErrorLogEntry(...) \
  ndis_testing::wdm_mock_object->IoAllocateErrorLogEntry_impl(__VA_ARGS__)

#define IoWriteErrorLogEntry(...) \
  ndis_testing::wdm_mock_object->IoWriteErrorLogEntry_impl(__VA_ARGS__)

#define RtlAppendUnicodeToString(...) \
  ndis_testing::wdm_mock_object->RtlAppendUnicodeToString_impl(__VA_ARGS__)

#define RtlAppendUnicodeStringToString(...)                           \
  ndis_testing::wdm_mock_object->RtlAppendUnicodeStringToString_impl( \
      __VA_ARGS__)

#define RtlCopyMemory(...) \
  ndis_testing::wdm_mock_object->RtlCopyMemory_impl(__VA_ARGS__)

#define RtlGetVersion(...) \
  ndis_testing::wdm_mock_object->RtlGetVersion_impl(__VA_ARGS__)

#define RtlInitEmptyAnsiString(...) \
  ndis_testing::wdm_mock_object->RtlInitEmptyAnsiString_impl(__VA_ARGS__)

#define RtlInitEmptyUnicodeString(...) \
  ndis_testing::wdm_mock_object->RtlInitEmptyUnicodeString_impl(__VA_ARGS__)

#define RtlIntegerToUnicodeString(...) \
  ndis_testing::wdm_mock_object->RtlIntegerToUnicodeString_impl(__VA_ARGS__)

#define RtlZeroMemory(...) \
  ndis_testing::wdm_mock_object->RtlZeroMemory_impl(__VA_ARGS__)

#define RtlQueryRegistryValues(...) \
  ndis_testing::wdm_mock_object->RtlQueryRegistryValues_impl(__VA_ARGS__)

#define RtlUnicodeStringToAnsiString(...) \
  ndis_testing::wdm_mock_object->RtlUnicodeStringToAnsiString_impl(__VA_ARGS__)

#define RtlUnicodeStringToInteger(...) \
  ndis_testing::wdm_mock_object->RtlUnicodeStringToInteger_impl(__VA_ARGS__)

#define RtlUnicodeToUTF8N(...) \
  ndis_testing::wdm_mock_object->RtlUnicodeToUTF8N_impl(__VA_ARGS__)

#endif  // THIRD_PARTY_CLOUD_WINDOWS_GVNIC_RELEASE_TESTING_WDM_H_
