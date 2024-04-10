#ifndef OS_INFORMATION_H_
#define OS_INFORMATION_H_

#include <ndis.h>

#define OS_VERSION_INFO_STR_CHAR_COUNT 128

class OsInformation final {
 public:
  OsInformation()
      : query_registry_table_(nullptr),
        major_version_(0),
        minor_version_(0),
        sub_version_(0),
        update_build_release_(nullptr),
        edition_display_(nullptr),
        registry_updated_(false) {}

  ~OsInformation() {
    PAGED_CODE();

    Release();
  }

  // Not copyable or movable
  OsInformation(const OsInformation&) = delete;
  OsInformation& operator=(const OsInformation&) = delete;

  NDIS_STATUS Initialize(NDIS_HANDLE miniport_handle);
  void Release();

  UINT32 major_version() const { return major_version_; }
  UINT32 minor_version() const { return minor_version_; }
  UINT32 sub_version() const { return sub_version_; }
  NTSTATUS update_build_release(UINT8** update_build_release);
  NTSTATUS edition_display(UINT8** edition_display);

 private:
  NTSTATUS query_wdm();
  NTSTATUS query_registry();

  RTL_QUERY_REGISTRY_TABLE* query_registry_table_;
  UINT32 major_version_;
  UINT32 minor_version_;
  UINT32 sub_version_;
  UINT8* update_build_release_;
  UINT8* edition_display_;
  bool registry_updated_;
};

#endif  // OS_INFORMATION_H_
