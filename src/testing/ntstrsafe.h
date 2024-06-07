#ifndef THIRD_PARTY_CLOUD_WINDOWS_GVNIC_RELEASE_TESTING_NTSTRSAFE_H_
#define THIRD_PARTY_CLOUD_WINDOWS_GVNIC_RELEASE_TESTING_NTSTRSAFE_H_

#include <stdarg.h>

#include "third_party/cloud_windows_gvnic/release/testing/ndis-types.h"

#define NTSTRSAFEDDI NTSTATUS

typedef wchar_t* NTSTRSAFE_PWSTR;
typedef const wchar_t* NTSTRSAFE_PCWSTR;

namespace ndis_testing {

class NtStrSafeStub {
 public:
  NtStrSafeStub() {}
  virtual ~NtStrSafeStub() {}
  virtual NTSTRSAFEDDI RtlStringCbVPrintfW_impl(NTSTRSAFE_PWSTR psz_dest,
                                                size_t cb_dest,
                                                NTSTRSAFE_PCWSTR psz_format,
                                                va_list arg_list);
};

extern NtStrSafeStub* ntstrsafe_mock_object;

}  // namespace ndis_testing

#define RtlStringCbVPrintfW(...) \
  ndis_testing::ntstrsafe_mock_object->RtlStringCbVPrintfW_impl(__VA_ARGS__)

#endif  // THIRD_PARTY_CLOUD_WINDOWS_GVNIC_RELEASE_TESTING_NTSTRSAFE_H_
