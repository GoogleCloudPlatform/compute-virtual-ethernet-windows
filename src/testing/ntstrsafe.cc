#include "third_party/cloud_windows_gvnic/release/testing/ntstrsafe.h"

#include <cwchar>

namespace ndis_testing {

NtStrSafeStub* ntstrsafe_mock_object = nullptr;

NTSTRSAFEDDI
NtStrSafeStub::RtlStringCbVPrintfW_impl(NTSTRSAFE_PWSTR psz_dest,
                                        size_t cb_dest,
                                        NTSTRSAFE_PCWSTR psz_format,
                                        va_list arg_list) {
  if (cb_dest > INT_MAX * sizeof(WCHAR) || psz_dest == nullptr ||
      psz_format == nullptr || (cb_dest == 0 && wcslen(psz_format) > 0)) {
    return STATUS_INVALID_PARAMETER;
  }
  int len =
      swprintf(psz_dest, cb_dest / sizeof(wchar_t) + 1, psz_format, arg_list);
  if (len < 0) {
    return STATUS_BUFFER_OVERFLOW;
  }
  return STATUS_SUCCESS;
}

}  // namespace ndis_testing
