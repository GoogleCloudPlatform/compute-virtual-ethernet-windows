#ifndef THIRD_PARTY_CLOUD_WINDOWS_GVNIC_RELEASE_TESTING_WDM_TYPES_H_
#define THIRD_PARTY_CLOUD_WINDOWS_GVNIC_RELEASE_TESTING_WDM_TYPES_H_

#include "third_party/cloud_windows_gvnic/release/testing/ndis-types.h"

typedef struct _IO_ERROR_LOG_PACKET {
  UCHAR MajorFunctionCode;
  UCHAR RetryCount;
  USHORT DumpDataSize;
  USHORT NumberOfStrings;
  USHORT StringOffset;
  USHORT EventCategory;
  NTSTATUS ErrorCode;
  ULONG UniqueErrorValue;
  NTSTATUS FinalStatus;
  ULONG SequenceNumber;
  ULONG IoControlCode;
  LARGE_INTEGER DeviceOffset;
  ULONG DumpData[1];
} IO_ERROR_LOG_PACKET, *PIO_ERROR_LOG_PACKET;

typedef struct _IO_ERROR_LOG_MESSAGE {
  USHORT Type;
  USHORT Size;
  USHORT DriverNameLength;
  LARGE_INTEGER TimeStamp;
  ULONG DriverNameOffset;
  IO_ERROR_LOG_PACKET EntryData;
} IO_ERROR_LOG_MESSAGE, *PIO_ERROR_LOG_MESSAGE;

#define ERROR_LOG_LIMIT_SIZE (256 - 16)

#define IO_ERROR_LOG_MESSAGE_HEADER_LENGTH                      \
  (sizeof(IO_ERROR_LOG_MESSAGE) - sizeof(IO_ERROR_LOG_PACKET) + \
   (sizeof(WCHAR) * 40))

#define ERROR_LOG_MESSAGE_LIMIT_SIZE \
  (ERROR_LOG_LIMIT_SIZE + IO_ERROR_LOG_MESSAGE_HEADER_LENGTH)

#define IO_ERROR_LOG_MESSAGE_LENGTH                             \
  ((PORT_MAXIMUM_MESSAGE_LENGTH > ERROR_LOG_MESSAGE_LIMIT_SIZE) \
       ? ERROR_LOG_MESSAGE_LIMIT_SIZE                           \
       : PORT_MAXIMUM_MESSAGE_LENGTH)

#define ERROR_LOG_MAXIMUM_SIZE \
  (IO_ERROR_LOG_MESSAGE_LENGTH - IO_ERROR_LOG_MESSAGE_HEADER_LENGTH)

#define PORT_MAXIMUM_MESSAGE_LENGTH 512

typedef enum _POOL_TYPE {
  NonPagedPool,
  NonPagedPoolExecute = NonPagedPool,
  PagedPool,
  NonPagedPoolMustSucceed = NonPagedPool + 2,
  DontUseThisType,
  NonPagedPoolCacheAligned = NonPagedPool + 4,
  PagedPoolCacheAligned,
  NonPagedPoolCacheAlignedMustS = NonPagedPool + 6,
  MaxPoolType,
  NonPagedPoolBase = 0,
  NonPagedPoolBaseMustSucceed = NonPagedPoolBase + 2,
  NonPagedPoolBaseCacheAligned = NonPagedPoolBase + 4,
  NonPagedPoolBaseCacheAlignedMustS = NonPagedPoolBase + 6,
  NonPagedPoolSession = 32,
  PagedPoolSession = NonPagedPoolSession + 1,
  NonPagedPoolMustSucceedSession = PagedPoolSession + 1,
  DontUseThisTypeSession = NonPagedPoolMustSucceedSession + 1,
  NonPagedPoolCacheAlignedSession = DontUseThisTypeSession + 1,
  PagedPoolCacheAlignedSession = NonPagedPoolCacheAlignedSession + 1,
  NonPagedPoolCacheAlignedMustSSession = PagedPoolCacheAlignedSession + 1,
  NonPagedPoolNx = 512,
  NonPagedPoolNxCacheAligned = NonPagedPoolNx + 4,
  NonPagedPoolSessionNx = NonPagedPoolNx + 32,
} POOL_TYPE;

#endif  // THIRD_PARTY_CLOUD_WINDOWS_GVNIC_RELEASE_TESTING_WDM_TYPES_H_
