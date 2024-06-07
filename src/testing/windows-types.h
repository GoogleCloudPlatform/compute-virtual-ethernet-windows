#ifndef THIRD_PARTY_CLOUD_WINDOWS_GVNIC_TESTING_WINDOWS_TYPES_H__
#define THIRD_PARTY_CLOUD_WINDOWS_GVNIC_TESTING_WINDOWS_TYPES_H__

#include <cstddef>
#include <cstdint>

typedef char CHAR;
typedef unsigned char UCHAR;

typedef int8_t CCHAR;
typedef int16_t CSHORT, INT16;
typedef int32_t LONG;
typedef int64_t LONGLONG;

typedef uint8_t UINT8;
typedef uint16_t USHORT, UINT16, WORD;
typedef uint32_t UINT, UINT32, DWORD, ULONG;
typedef uint64_t UINT64, ULONGLONG, ULONG64, ULONG_PTR;

typedef wchar_t WCHAR;
typedef CHAR *PCHAR;
typedef WCHAR *PWSTR, *PWCHAR;
typedef const WCHAR *PCWSTR;
typedef UCHAR *PUCHAR;
typedef USHORT *PUSHORT;
typedef UINT *PUINT;
typedef ULONG *PULONG;

typedef void VOID;
typedef void *PVOID;

typedef ULONG_PTR SIZE_T, *PSIZE_T;

typedef UCHAR BOOLEAN;
typedef enum { FALSE, TRUE } BOOL;
typedef BOOLEAN *PBOOLEAN;

#define MAXUINT16 UINT16_MAX
#define MAXUINT32 UINT32_MAX
#define MAXUINT64 UINT64_MAX

typedef union _LARGE_INTEGER {
  struct {
    DWORD LowPart;
    LONG HighPart;
  } u;
  LONGLONG QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;

typedef LARGE_INTEGER PHYSICAL_ADDRESS, *PPHYSICAL_ADDRESS;

typedef struct _LIST_ENTRY {
  struct _LIST_ENTRY *Flink;
  struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY, PRLIST_ENTRY;
typedef struct _SINGLE_LIST_ENTRY {
  struct _SINGLE_LIST_ENTRY *Next;
} SLIST_ENTRY, SINGLE_LIST_ENTRY, *PSLIST_ENTRY, *PSINGLE_LIST_ENTRY;

typedef union _SLIST_HEADER {
  ULONGLONG Alignment;
  struct {
    SLIST_ENTRY Next;
    WORD Depth;
    WORD Sequence;
  };
} SLIST_HEADER, *PSLIST_HEADER;

#define InitializeSListHead(_SListHead) \
  {                                     \
    (_SListHead)->Next.Next = nullptr;  \
    (_SListHead)->Depth = 0;            \
    (_SListHead)->Sequence = 0;         \
  }

#define InitializeListHead(_ListHead) \
  {                                   \
    (_ListHead)->Flink = (_ListHead); \
    (_ListHead)->Blink = (_ListHead); \
  }
#define InsertTailList(_ListHead, _Entry) \
  {                                       \
    PLIST_ENTRY _OldBlink;                \
    _OldBlink = (_ListHead)->Blink;       \
    (_Entry)->Flink = (_ListHead);        \
    (_Entry)->Blink = _OldBlink;          \
    _OldBlink->Flink = (_Entry);          \
    (_ListHead)->Blink = (_Entry);        \
  }
#define IsListEmpty(_ListHead) ((_ListHead)->Flink == (_ListHead))

static __inline PLIST_ENTRY RemoveHeadList(
    /*IN*/ PLIST_ENTRY ListHead) {
  PLIST_ENTRY OldFlink;
  PLIST_ENTRY OldBlink;
  PLIST_ENTRY Entry;

  Entry = ListHead->Flink;
  OldFlink = ListHead->Flink->Flink;
  OldBlink = ListHead->Flink->Blink;
  OldFlink->Blink = OldBlink;
  OldBlink->Flink = OldFlink;

  if (Entry != ListHead) {
    Entry->Flink = NULL;
    Entry->Blink = NULL;
  }

  return Entry;
}

static __inline BOOLEAN RemoveEntryList(PLIST_ENTRY Entry) {
  Entry->Blink->Flink = Entry->Flink;
  Entry->Flink->Blink = Entry->Blink;

  return Entry->Flink == Entry->Blink;
}

static __inline VOID InsertHeadList(PLIST_ENTRY ListHead, PLIST_ENTRY Entry) {
  PLIST_ENTRY Flink;

  Flink = ListHead->Flink;
  Entry->Flink = Flink;
  Entry->Blink = ListHead;
  Flink->Blink = Entry;
  ListHead->Flink = Entry;
}

static __inline PLIST_ENTRY ExInterlockedRemoveHeadList(
    /*IN*/ PLIST_ENTRY ListHead) {
  PLIST_ENTRY OldFlink;
  PLIST_ENTRY OldBlink;
  PLIST_ENTRY Entry;

  Entry = ListHead->Flink;
  OldFlink = ListHead->Flink->Flink;
  OldBlink = ListHead->Flink->Blink;
  OldFlink->Blink = OldBlink;
  OldBlink->Flink = OldFlink;

  if (Entry != ListHead) {
    Entry->Flink = NULL;
    Entry->Blink = NULL;
  } else {
    return nullptr;
  }

  return Entry;
}

static __inline PSINGLE_LIST_ENTRY PopEntryList(PSINGLE_LIST_ENTRY ListHead) {
  PSINGLE_LIST_ENTRY Entry;

  Entry = ListHead->Next;
  if (Entry != NULL) {
    ListHead->Next = Entry->Next;
  }
  return Entry;
}

#define PushEntryList(_ListHead, _Entry) \
  {                                      \
    (_Entry)->Next = (_ListHead)->Next;  \
    (_ListHead)->Next = (_Entry);        \
  }

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING, *PCUNICODE_STRING;

typedef struct _STRING {
  USHORT Length;
  USHORT MaximumLength;
  PCHAR Buffer;
} STRING, ANSI_STRING, *PANSI_STRING;

typedef struct {
  USHORT Length;
  PVOID Buffer;
} BINARY_DATA;

typedef enum _MM_PAGE_PRIORITY {
  LowPagePriority,
  NormalPagePriority = 16,
  HighPagePriority = 32
} MM_PAGE_PRIORITY;

typedef struct _GUID {
  UINT32 Data1;
  UINT16 Data2;
  UINT16 Data3;
  unsigned char Data4[8];
} GUID;

#define ALL_PROCESSOR_GROUPS 0xffff
typedef ULONG_PTR KAFFINITY;
typedef KAFFINITY *PKAFFINITY;
typedef struct _GROUP_AFFINITY {
  KAFFINITY Mask;
  USHORT Group;
  USHORT Reserved[3];
} GROUP_AFFINITY, *PGROUP_AFFINITY;

#define PRTL_QUERY_REGISTRY_ROUTINE PVOID

typedef struct _RTL_QUERY_REGISTRY_TABLE {
  PRTL_QUERY_REGISTRY_ROUTINE QueryRoutine;
  ULONG Flags;
  PWSTR Name;
  PVOID EntryContext;
  ULONG DefaultType;
  PVOID DefaultData;
  ULONG DefaultLength;
} RTL_QUERY_REGISTRY_TABLE, *PRTL_QUERY_REGISTRY_TABLE;

#define MdlMappingNoWrite 0x80000000
#define MdlMappingNoExecute 0x40000000

#define PAGE_SIZE 0x1000
#define PAGE_SHIFT 12L

#define PASSIVE_LEVEL 0
#define LOW_LEVEL 0
#define APC_LEVEL 1
#define DISPATCH_LEVEL 2
#define SYNCH_LEVEL 27
#define PROFILE_LEVEL 27
#define CLOCK1_LEVEL 28
#define CLOCK2_LEVEL 28
#define IPI_LEVEL 29
#define POWER_LEVEL 30
#define HIGH_LEVEL 31

//  Registry Data Types
#define REG_NONE (0ul)
#define REG_SZ (1ul)
#define REG_EXPAND_SZ (2ul)
#define REG_BINARY (3ul)
#define REG_DWORD (4ul)
#define REG_DWORD_LITTLE_ENDIAN (4ul)
#define REG_DWORD_BIG_ENDIAN (5ul)
#define REG_LINK (6ul)
#define REG_MULTI_SZ (7ul)
#define REG_RESOURCE_LIST (8ul)
#define REG_FULL_RESOURCE_DESCRIPTOR (9ul)
#define REG_RESOURCE_REQUIREMENTS_LIST (10ul)
#define REG_QWORD (11ul)
#define REG_QWORD_LITTLE_ENDIAN (11ul)

//  Registry Query Types
#define RTL_QUERY_REGISTRY_SUBKEY 0x00000001
#define RTL_QUERY_REGISTRY_TOPKEY 0x00000002
#define RTL_QUERY_REGISTRY_REQUIRED 0x00000004
#define RTL_QUERY_REGISTRY_NOVALUE 0x00000008
#define RTL_QUERY_REGISTRY_NOEXPAND 0x00000010
#define RTL_QUERY_REGISTRY_DIRECT 0x00000020
#define RTL_QUERY_REGISTRY_DELETE 0x00000040
#define RTL_QUERY_REGISTRY_NOSTRING 0x00000080

//  Registry Key Tree Paths
#define RTL_REGISTRY_ABSOLUTE 0
#define RTL_REGISTRY_SERVICES 1
#define RTL_REGISTRY_CONTROL 2
#define RTL_REGISTRY_WINDOWS_NT 3
#define RTL_REGISTRY_DEVICEMAP 4
#define RTL_REGISTRY_USER 5
#define RTL_REGISTRY_MAXIMUM 6
#define RTL_REGISTRY_HANDLE 0x40000000
#define RTL_REGISTRY_OPTIONAL 0x80000000

#endif  // THIRD_PARTY_CLOUD_WINDOWS_GVNIC_TESTING_WINDOWS_TYPES_H__
