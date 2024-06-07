#ifndef THIRD_PARTY_CLOUD_WINDOWS_GVNIC_TESTING_NDIS_TYPES_H__
#define THIRD_PARTY_CLOUD_WINDOWS_GVNIC_TESTING_NDIS_TYPES_H__

#include "third_party/absl/synchronization/mutex.h"
#include "third_party/cloud_windows_gvnic/release/testing/windows-types.h"

typedef PVOID NDIS_HANDLE, *PNDIS_HANDLE;
typedef PHYSICAL_ADDRESS NDIS_PHYSICAL_ADDRESS, *PNDIS_PHYSICAL_ADDRESS;
typedef int NDIS_STATUS, *PNDIS_STATUS;
typedef UNICODE_STRING NDIS_STRING, *PNDIS_STRING;
typedef ULONG NDIS_OID, *PNDIS_OID;
typedef LONG NTSTATUS;

//  Structure to be used for OID_GEN_SUPPORTED_GUIDS.
//  This structure describes an OID to GUID mapping.
//  Or a Status to GUID mapping.
//  When ndis receives a request for a give GUID it will
//  query the miniport with the supplied OID.
//
typedef struct _NDIS_GUID {
  GUID Guid;
  union {
    NDIS_OID Oid;
    NDIS_STATUS Status;
  };
  ULONG Size;  //  Size of the data element. If the GUID
               //  represents an array then this is the
               //  size of an element in the array.
               //  This is -1 for strings.
  ULONG Flags;
} NDIS_GUID, *PNDIS_GUID;

#define fNDIS_GUID_TO_OID 0x00000001
#define fNDIS_GUID_TO_STATUS 0x00000002
#define fNDIS_GUID_ANSI_STRING 0x00000004
#define fNDIS_GUID_UNICODE_STRING 0x00000008
#define fNDIS_GUID_ARRAY 0x00000010
#define fNDIS_GUID_ALLOW_READ 0x00000020
#define fNDIS_GUID_ALLOW_WRITE 0x00000040
#define fNDIS_GUID_METHOD 0x00000080
#define fNDIS_GUID_NDIS_RESERVED 0x00000100
#define fNDIS_GUID_SUPPORT_COMMON_HEADER 0x00000200

typedef struct _PROCESSOR_NUMBER {
  USHORT Group;
  UCHAR Number;
  UCHAR Reserved;
} PROCESSOR_NUMBER, *PPROCESSOR_NUMBER;

typedef struct _NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO {
  union {
    struct {
      ULONG IsIPv4 : 1;
      ULONG IsIPv6 : 1;
      ULONG TcpChecksum : 1;
      ULONG UdpChecksum : 1;
      ULONG IpHeaderChecksum : 1;
      ULONG Reserved : 11;
      ULONG TcpHeaderOffset : 10;
    } Transmit;

    struct {
      ULONG TcpChecksumFailed : 1;
      ULONG UdpChecksumFailed : 1;
      ULONG IpChecksumFailed : 1;
      ULONG TcpChecksumSucceeded : 1;
      ULONG UdpChecksumSucceeded : 1;
      ULONG IpChecksumSucceeded : 1;
      ULONG Loopback : 1;
      ULONG TcpChecksumValueInvalid : 1;
      ULONG IpChecksumValueInvalid : 1;
    } Receive;

    PVOID Value;
  };
} NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO,
    *PNDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO;

typedef struct _MDL {
  struct _MDL *Next;
  CSHORT Size;
  CSHORT MdlFlags;
  struct _EPROCESS *Process;
  PVOID MappedSystemVa;
  PVOID StartVa;
  ULONG ByteCount;
  ULONG ByteOffset;
} MDL, *PMDL;

typedef struct NetBufferFreeMdl {
  MDL *Mdl;
} NET_BUFFER_FREE_MDL;

typedef struct NetBufferAllocateMdl {
  ULONG *BufferSize;
} NET_BUFFER_ALLOCATE_MDL;

typedef struct _NET_BUFFER NET_BUFFER, *PNET_BUFFER;
typedef struct _NET_BUFFER_LIST_CONTEXT NET_BUFFER_LIST_CONTEXT,
    *PNET_BUFFER_LIST_CONTEXT;
typedef struct _NET_BUFFER_LIST NET_BUFFER_LIST, *PNET_BUFFER_LIST;

typedef struct _SCATTER_GATHER_ELEMENT {
  PHYSICAL_ADDRESS Address;
  ULONG Length;
  ULONG_PTR Reserved;
} SCATTER_GATHER_ELEMENT, *PSCATTER_GATHER_ELEMENT;

typedef struct _SCATTER_GATHER_LIST {
  ULONG NumberOfElements;
  ULONG_PTR Reserved;
  SCATTER_GATHER_ELEMENT Elements[];
} SCATTER_GATHER_LIST, *PSCATTER_GATHER_LIST;
typedef struct _SCATTER_GATHER_LIST SCATTER_GATHER_LIST, *PSCATTER_GATHER_LIST;

typedef union _NET_BUFFER_DATA_LENGTH {
  ULONG DataLength;
  SIZE_T stDataLength;
} NET_BUFFER_DATA_LENGTH, *PNET_BUFFER_DATA_LENGTH;

typedef struct _NET_BUFFER_DATA {
  PNET_BUFFER Next;
  PMDL CurrentMdl;
  ULONG CurrentMdlOffset;
  NET_BUFFER_DATA_LENGTH NbDataLength;
  PMDL MdlChain;
  ULONG DataOffset;
} NET_BUFFER_DATA, *PNET_BUFFER_DATA;

typedef union _NET_BUFFER_HEADER {
  NET_BUFFER_DATA NetBufferData;
  SLIST_HEADER Link;
} NET_BUFFER_HEADER, *PNET_BUFFER_HEADER;

typedef struct _NET_BUFFER_SHARED_MEMORY NET_BUFFER_SHARED_MEMORY,
    *PNET_BUFFER_SHARED_MEMORY;

typedef struct _NET_BUFFER_SHARED_MEMORY {
  PNET_BUFFER_SHARED_MEMORY NextSharedMemorySegment;
  ULONG SharedMemoryFlags;
  NDIS_HANDLE SharedMemoryHandle;
  ULONG SharedMemoryOffset;
  ULONG SharedMemoryLength;
} NET_BUFFER_SHARED_MEMORY, *PNET_BUFFER_SHARED_MEMORY;

typedef struct _NET_BUFFER {
  union {
    struct {
      PNET_BUFFER Next;
      PMDL CurrentMdl;
      ULONG CurrentMdlOffset;
      union {
        ULONG DataLength;
        SIZE_T stDataLength;
      };

      PMDL MdlChain;
      ULONG DataOffset;
    };

    SLIST_HEADER Link;

    // Duplicate of the above union, for source-compatibility
    NET_BUFFER_HEADER NetBufferHeader;
  };

  USHORT ChecksumBias;
  USHORT Reserved;
  NDIS_HANDLE NdisPoolHandle;
  PVOID NdisReserved[2];
  PVOID ProtocolReserved[6];
  PVOID MiniportReserved[4];
  NDIS_PHYSICAL_ADDRESS DataPhysicalAddress;

  union {
    PNET_BUFFER_SHARED_MEMORY SharedMemoryInfo;
    PSCATTER_GATHER_LIST ScatterGatherList;
  };
} NET_BUFFER, *PNET_BUFFER;

typedef enum _NDIS_NET_BUFFER_LIST_INFO {
  TcpIpChecksumNetBufferListInfo,
  TcpLargeSendNetBufferListInfo,
  NetBufferListHashValue,
  NetBufferListHashInfo,
  TcpRecvSegCoalesceInfo,
  MaxNetBufferListInfo
} NDIS_NET_BUFFER_LIST_INFO,
    *PNDIS_NET_BUFFER_LIST_INFO;

typedef struct _NET_BUFFER_LIST_DATA {
  PNET_BUFFER_LIST Next;
  PNET_BUFFER FirstNetBuffer;
} NET_BUFFER_LIST_DATA, *PNET_BUFFER_LIST_DATA;

typedef union _NET_BUFFER_LIST_HEADER {
  NET_BUFFER_LIST_DATA NetBufferListData;
  SLIST_HEADER Link;
} NET_BUFFER_LIST_HEADER, *PNET_BUFFER_LIST_HEADER;

typedef struct _NET_BUFFER_LIST {
  union {
    struct {
      PNET_BUFFER_LIST Next;
      PNET_BUFFER FirstNetBuffer;
    };
    SLIST_HEADER Link;
    NET_BUFFER_LIST_HEADER NetBufferListHeader;
  };
  PNET_BUFFER_LIST_CONTEXT Context;
  PNET_BUFFER_LIST ParentNetBufferList;
  NDIS_HANDLE NdisPoolHandle;
  PVOID NdisReserved[2];
  PVOID ProtocolReserved[4];
  PVOID MiniportReserved[2];
  PVOID Scratch;
  NDIS_HANDLE SourceHandle;
  ULONG NblFlags;
  LONG ChildRefCount;
  ULONG Flags;
  union {
    NDIS_STATUS Status;
    ULONG NdisReserved2;
  };
  PVOID NetBufferListInfo[MaxNetBufferListInfo];
} NET_BUFFER_LIST, *PNET_BUFFER_LIST;

typedef union _NDIS_RSC_NBL_INFO {
  struct {
    USHORT CoalescedSegCount;
    USHORT DupAckCount;
  } Info;
  PVOID Value;
} NDIS_RSC_NBL_INFO, *PNDIS_RSC_NBL_INFO;

#define NET_BUFFER_NEXT_NB(_NB) ((_NB)->Next)
#define NET_BUFFER_FIRST_MDL(_NB) ((_NB)->MdlChain)
#define NET_BUFFER_DATA_LENGTH(_NB) ((_NB)->DataLength)
#define NET_BUFFER_DATA_OFFSET(_NB) ((_NB)->DataOffset)
#define NET_BUFFER_CURRENT_MDL(_NB) ((_NB)->CurrentMdl)
#define NET_BUFFER_CURRENT_MDL_OFFSET(_NB) ((_NB)->CurrentMdlOffset)
#define NET_BUFFER_LIST_NEXT_NBL(_NBL) ((_NBL)->Next)
#define NET_BUFFER_LIST_FIRST_NB(_NBL) ((_NBL)->FirstNetBuffer)
#define NET_BUFFER_LIST_STATUS(_NBL) ((_NBL)->Status)
#define NET_BUFFER_LIST_INFO(_NBL, _Id) ((_NBL)->NetBufferListInfo[(_Id)])
#define NET_BUFFER_LIST_COALESCED_SEG_COUNT(_NBL)         \
  (((PNDIS_RSC_NBL_INFO) &                                \
    NET_BUFFER_LIST_INFO((_NBL), TcpRecvSegCoalesceInfo)) \
       ->Info.CoalescedSegCount)
#define NET_BUFFER_LIST_DUP_ACK_COUNT(_NBL)         \
  (((PNDIS_RSC_NBL_INFO) &                                \
    NET_BUFFER_LIST_INFO((_NBL), TcpRecvSegCoalesceInfo)) \
       ->Info.DupAckCount)
#define NET_BUFFER_LIST_MINIPORT_RESERVED(_NBL) ((_NBL)->MiniportReserved)

#define NET_BUFFER_PROTOCOL_RESERVED(_NB) ((_NB)->ProtocolReserved)
#define NET_BUFFER_MINIPORT_RESERVED(_NB) ((_NB)->MiniportReserved)
#define NET_BUFFER_CHECKSUM_BIAS(_NB) ((_NB)->ChecksumBias)

typedef enum _EX_POOL_PRIORITY {
  LowPoolPriority,
  LowPoolPrioritySpecialPoolOverrun = 8,
  LowPoolPrioritySpecialPoolUnderrun = 9,
  NormalPoolPriority = 16,
  NormalPoolPrioritySpecialPoolOverrun = 24,
  NormalPoolPrioritySpecialPoolUnderrun = 25,
  HighPoolPriority = 32,
  HighPoolPrioritySpecialPoolOverrun = 40,
  HighPoolPrioritySpecialPoolUnderrun = 41
} EX_POOL_PRIORITY;

typedef enum _NDIS_PARAMETER_TYPE {
  NdisParameterInteger,
  NdisParameterHexInteger,
  NdisParameterString,
  NdisParameterMultiString,
  NdisParameterBinary
} NDIS_PARAMETER_TYPE,
    *PNDIS_PARAMETER_TYPE;

typedef struct _NDIS_CONFIGURATION_PARAMETER {
  NDIS_PARAMETER_TYPE ParameterType;
  union {
    ULONG IntegerData;
    NDIS_STRING StringData;
    BINARY_DATA BinaryData;
  } ParameterData;
} NDIS_CONFIGURATION_PARAMETER, *PNDIS_CONFIGURATION_PARAMETER;

typedef struct _NDIS_OBJECT_HEADER {
  UCHAR Type;
  UCHAR Revision;
  USHORT Size;
} NDIS_OBJECT_HEADER, *PNDIS_OBJECT_HEADER;

typedef struct _NDIS_CONFIGURATION_OBJECT {
  NDIS_OBJECT_HEADER Header;
  NDIS_HANDLE NdisHandle;
  ULONG Flags;
} NDIS_CONFIGURATION_OBJECT, *PNDIS_CONFIGURATION_OBJECT;

typedef UCHAR KIRQL, *PKIRQL;
// KSPIN_LOCK is opaque and kernel-based, using a pointer to absl::Mutex to
// emulate allocation and locking during unit tests.
typedef absl::Mutex *KSPIN_LOCK;
typedef struct _NDIS_SPIN_LOCK {
  KSPIN_LOCK SpinLock;
  KIRQL OldIrql;
} NDIS_SPIN_LOCK, *PNDIS_SPIN_LOCK;

typedef struct _NDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO {
  union {
    struct {
      ULONG Unused : 30;
      ULONG Type : 1;
      ULONG Reserved2 : 1;
    } Transmit;
    struct {
      ULONG MSS : 20;
      ULONG TcpHeaderOffset : 10;
      ULONG Type : 1;
      ULONG Reserved2 : 1;
    } LsoV1Transmit;
    struct {
      ULONG TcpPayload : 30;
      ULONG Type : 1;
      ULONG Reserved2 : 1;
    } LsoV1TransmitComplete;
    struct {
      ULONG MSS : 20;
      ULONG TcpHeaderOffset : 10;
      ULONG Type : 1;
      ULONG IPVersion : 1;
    } LsoV2Transmit;
    struct {
      ULONG Reserved : 30;
      ULONG Type : 1;
      ULONG Reserved2 : 1;
    } LsoV2TransmitComplete;
    PVOID Value;
  };
} NDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO,
    *PNDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO;

typedef struct _NDIS_STATISTICS_INFO {
  NDIS_OBJECT_HEADER Header;
  ULONG SupportedStatistics;
  ULONG64 ifInDiscards;
  ULONG64 ifInErrors;
  ULONG64 ifHCInOctets;
  ULONG64 ifHCInUcastPkts;
  ULONG64 ifHCInMulticastPkts;
  ULONG64 ifHCInBroadcastPkts;
  ULONG64 ifHCOutOctets;
  ULONG64 ifHCOutUcastPkts;
  ULONG64 ifHCOutMulticastPkts;
  ULONG64 ifHCOutBroadcastPkts;
  ULONG64 ifOutErrors;
  ULONG64 ifOutDiscards;
  ULONG64 ifHCInUcastOctets;
  ULONG64 ifHCInMulticastOctets;
  ULONG64 ifHCInBroadcastOctets;
  ULONG64 ifHCOutUcastOctets;
  ULONG64 ifHCOutMulticastOctets;
  ULONG64 ifHCOutBroadcastOctets;
} NDIS_STATISTICS_INFO, *PNDIS_STATISTICS_INFO;

typedef struct _CM_PARTIAL_RESOURCE_DESCRIPTOR {
  UCHAR Type;
  UCHAR ShareDisposition;
  USHORT Flags;
  union {
    struct {
      PHYSICAL_ADDRESS Start;
      ULONG Length;
    } Generic;
    struct {
      PHYSICAL_ADDRESS Start;
      ULONG Length;
    } Port;
    struct {
      ULONG Level;
      ULONG Vector;
      ULONG Affinity;
    } Interrupt;
    struct {
      union {
        struct {
          USHORT Group;
          USHORT Reserved;
          USHORT MessageCount;
          ULONG Vector;
          ULONG Affinity;
        } Raw;
        struct {
          ULONG Level;
          ULONG Vector;
          ULONG Affinity;
        } Translated;
      };
    } MessageInterrupt;
    struct {
      PHYSICAL_ADDRESS Start;
      ULONG Length;
    } Memory;
    struct {
      ULONG Channel;
      ULONG Port;
      ULONG Reserved1;
    } Dma;
    struct {
      ULONG Data[3];
    } DevicePrivate;
    struct {
      ULONG Start;
      ULONG Length;
      ULONG Reserved;
    } BusNumber;
    struct {
      ULONG DataSize;
      ULONG Reserved1;
      ULONG Reserved2;
    } DeviceSpecificData;
  } u;
} CM_PARTIAL_RESOURCE_DESCRIPTOR, *PCM_PARTIAL_RESOURCE_DESCRIPTOR;

typedef struct _CM_PARTIAL_RESOURCE_LIST {
  USHORT Version;
  USHORT Revision;
  ULONG Count;
  CM_PARTIAL_RESOURCE_DESCRIPTOR PartialDescriptors[1];
} CM_PARTIAL_RESOURCE_LIST, *PCM_PARTIAL_RESOURCE_LIST;
typedef CM_PARTIAL_RESOURCE_LIST NDIS_RESOURCE_LIST, *PNDIS_RESOURCE_LIST;

typedef struct _KINTERRUPT *PKINTERRUPT;

typedef enum _KINTERRUPT_MODE { LevelSensitive, Latched } KINTERRUPT_MODE;
typedef enum _KINTERRUPT_POLARITY {
  InterruptPolarityUnknown,
  InterruptActiveHigh,
  InterruptRisingEdge = InterruptActiveHigh,
  InterruptActiveLow,
  InterruptFallingEdge = InterruptActiveLow,
  InterruptActiveBoth,
  InterruptActiveBothTriggerLow = InterruptActiveBoth,
  InterruptActiveBothTriggerHigh,
} KINTERRUPT_POLARITY,
    *PKINTERRUPT_POLARITY;

typedef struct _IO_INTERRUPT_MESSAGE_INFO_ENTRY {
  PHYSICAL_ADDRESS MessageAddress;
  KAFFINITY TargetProcessorSet;
  PKINTERRUPT InterruptObject;
  ULONG MessageData;
  ULONG Vector;
  KIRQL Irql;
  KINTERRUPT_MODE Mode;
  KINTERRUPT_POLARITY Polarity;
} IO_INTERRUPT_MESSAGE_INFO_ENTRY, *PIO_INTERRUPT_MESSAGE_INFO_ENTRY;

typedef struct _IO_INTERRUPT_MESSAGE_INFO {
  KIRQL UnifiedIrql;
  ULONG MessageCount;
  IO_INTERRUPT_MESSAGE_INFO_ENTRY MessageInfo[1];
} IO_INTERRUPT_MESSAGE_INFO, *PIO_INTERRUPT_MESSAGE_INFO;

typedef struct _DEVICE_OBJECT {
  CSHORT Type;
  USHORT Size;
} DEVICE_OBJECT;
typedef struct _DEVICE_OBJECT *PDEVICE_OBJECT;

typedef struct _DRIVER_OBJECT {
  CSHORT Type;
  CSHORT Size;
  PDEVICE_OBJECT DeviceObject;
  ULONG Flags;
  PVOID DriverStart;
  ULONG DriverSize;
  PVOID DriverSection;
  UNICODE_STRING DriverName;
} DRIVER_OBJECT;
typedef struct _DRIVER_OBJECT *PDRIVER_OBJECT;

typedef struct _NET_BUFFER_LIST_POOL_PARAMETERS {
  NDIS_OBJECT_HEADER Header;
  UCHAR ProtocolId;
  BOOLEAN fAllocateNetBuffer;
  USHORT ContextSize;
  ULONG PoolTag;
  ULONG DataSize;
} NET_BUFFER_LIST_POOL_PARAMETERS, *PNET_BUFFER_LIST_POOL_PARAMETERS;

typedef VOID(MINIPORT_PROCESS_SG_LIST)(PDEVICE_OBJECT pDO, PVOID Reserved,
                                       PSCATTER_GATHER_LIST pSGL,
                                       PVOID Context);
typedef MINIPORT_PROCESS_SG_LIST(*MINIPORT_PROCESS_SG_LIST_HANDLER);

typedef VOID(MINIPORT_ALLOCATE_SHARED_MEM_COMPLETE)(
    NDIS_HANDLE MiniportAdapterContext, PVOID VirtualAddress,
    PNDIS_PHYSICAL_ADDRESS PhysicalAddress, ULONG Length, PVOID Context);
typedef MINIPORT_ALLOCATE_SHARED_MEM_COMPLETE(
    *MINIPORT_ALLOCATE_SHARED_MEM_COMPLETE_HANDLER);

#define NDIS_SG_DMA_64_BIT_ADDRESS 0x00000001
typedef struct _NDIS_SG_DMA_DESCRIPTION {
  NDIS_OBJECT_HEADER Header;
  ULONG Flags;
  ULONG MaximumPhysicalMapping;
  MINIPORT_PROCESS_SG_LIST_HANDLER ProcessSGListHandler;
  MINIPORT_ALLOCATE_SHARED_MEM_COMPLETE_HANDLER
  SharedMemAllocateCompleteHandler;
  ULONG ScatterGatherListSize;
} NDIS_SG_DMA_DESCRIPTION, *PNDIS_SG_DMA_DESCRIPTION;

typedef BOOLEAN(MINIPORT_ISR)(NDIS_HANDLE MiniportInterruptContext,
                              PBOOLEAN QueueDefaultInterruptDpc,
                              PULONG TargetProcessors);
typedef MINIPORT_ISR(*MINIPORT_ISR_HANDLER);

typedef VOID(MINIPORT_INTERRUPT_DPC)(NDIS_HANDLE MiniportInterruptContext,
                                     PVOID MiniportDpcContext,
                                     PVOID ReceiveThrottleParameters,
                                     PVOID NdisReserved2);
typedef MINIPORT_INTERRUPT_DPC(*MINIPORT_INTERRUPT_DPC_HANDLER);

typedef VOID(MINIPORT_DISABLE_INTERRUPT)(NDIS_HANDLE MiniportInterruptContext);
typedef MINIPORT_DISABLE_INTERRUPT(*MINIPORT_DISABLE_INTERRUPT_HANDLER);

typedef VOID(MINIPORT_ENABLE_INTERRUPT)(NDIS_HANDLE MiniportInterruptContext);
typedef MINIPORT_ENABLE_INTERRUPT(*MINIPORT_ENABLE_INTERRUPT_HANDLER);

typedef BOOLEAN(MINIPORT_MESSAGE_INTERRUPT)(
    NDIS_HANDLE MiniportInterruptContext, ULONG MessageId,
    PBOOLEAN QueueDefaultInterruptDpc, PULONG TargetProcessors);
typedef MINIPORT_MESSAGE_INTERRUPT(*MINIPORT_MSI_ISR_HANDLER);

typedef VOID(MINIPORT_MESSAGE_INTERRUPT_DPC)(
    NDIS_HANDLE MiniportInterruptContext, ULONG MessageId,
    PVOID MiniportDpcContext, PVOID ReceiveThrottleParameters,
    PVOID NdisReserved2

);
typedef MINIPORT_MESSAGE_INTERRUPT_DPC(*MINIPORT_MSI_INTERRUPT_DPC_HANDLER);

typedef VOID(MINIPORT_DISABLE_MESSAGE_INTERRUPT)(
    NDIS_HANDLE MiniportInterruptContext, ULONG MessageId);
typedef MINIPORT_DISABLE_MESSAGE_INTERRUPT(
    *MINIPORT_DISABLE_MSI_INTERRUPT_HANDLER);

typedef VOID(MINIPORT_ENABLE_MESSAGE_INTERRUPT)(
    NDIS_HANDLE MiniportInterruptContext, ULONG MessageId);
typedef MINIPORT_ENABLE_MESSAGE_INTERRUPT(
    *MINIPORT_ENABLE_MSI_INTERRUPT_HANDLER);

typedef enum _NDIS_INTERRUPT_TYPE {
  NDIS_CONNECT_LINE_BASED = 1,
  NDIS_CONNECT_MESSAGE_BASED
} NDIS_INTERRUPT_TYPE,
    *PNDIS_INTERRUPT_TYPE;

typedef struct _NDIS_MINIPORT_INTERRUPT_CHARACTERISTICS {
  NDIS_OBJECT_HEADER Header;
  MINIPORT_ISR_HANDLER InterruptHandler;
  MINIPORT_INTERRUPT_DPC_HANDLER InterruptDpcHandler;
  MINIPORT_DISABLE_INTERRUPT_HANDLER DisableInterruptHandler;
  MINIPORT_ENABLE_INTERRUPT_HANDLER EnableInterruptHandler;
  BOOLEAN MsiSupported;
  BOOLEAN MsiSyncWithAllMessages;
  MINIPORT_MSI_ISR_HANDLER MessageInterruptHandler;
  MINIPORT_MSI_INTERRUPT_DPC_HANDLER MessageInterruptDpcHandler;
  MINIPORT_DISABLE_MSI_INTERRUPT_HANDLER DisableMessageInterruptHandler;
  MINIPORT_ENABLE_MSI_INTERRUPT_HANDLER EnableMessageInterruptHandler;
  NDIS_INTERRUPT_TYPE InterruptType;
  PIO_INTERRUPT_MESSAGE_INFO MessageInfoTable;
} NDIS_MINIPORT_INTERRUPT_CHARACTERISTICS,
    *PNDIS_MINIPORT_INTERRUPT_CHARACTERISTICS;

typedef struct _NDIS_RECEIVE_SCALE_CAPABILITIES {
  NDIS_OBJECT_HEADER Header;
  ULONG CapabilitiesFlags;
  ULONG NumberOfInterruptMessages;
  ULONG NumberOfReceiveQueues;
  USHORT NumberOfIndirectionTableEntries;
} NDIS_RECEIVE_SCALE_CAPABILITIES, *PNDIS_RECEIVE_SCALE_CAPABILITIES;

typedef struct _NDIS_RECEIVE_SCALE_PARAMETERS {
  NDIS_OBJECT_HEADER Header;
  USHORT Flags;
  USHORT BaseCpuNumber;
  ULONG HashInformation;
  USHORT IndirectionTableSize;
  ULONG IndirectionTableOffset;
  USHORT HashSecretKeySize;
  ULONG HashSecretKeyOffset;
  ULONG ProcessorMasksOffset;
  ULONG NumberOfProcessorMasks;
  ULONG ProcessorMasksEntrySize;
} NDIS_RECEIVE_SCALE_PARAMETERS, *PNDIS_RECEIVE_SCALE_PARAMETERS;

typedef ULONG NDIS_PORT_NUMBER;

typedef struct _NDIS_STATUS_INDICATION {
  NDIS_OBJECT_HEADER Header;
  NDIS_HANDLE SourceHandle;
  NDIS_PORT_NUMBER PortNumber;
  NDIS_STATUS StatusCode;
  ULONG Flags;
  NDIS_HANDLE DestinationHandle;
  PVOID RequestId;
  PVOID StatusBuffer;
  ULONG StatusBufferSize;
  GUID Guid;
  PVOID NdisReserved[4];
} NDIS_STATUS_INDICATION, *PNDIS_STATUS_INDICATION;

typedef struct _NDIS_TCP_IP_CHECKSUM_OFFLOAD {
  struct {
    ULONG Encapsulation;
    ULONG IpOptionsSupported : 2;
    ULONG TcpOptionsSupported : 2;
    ULONG TcpChecksum : 2;
    ULONG UdpChecksum : 2;
    ULONG IpChecksum : 2;
  } IPv4Transmit;
  struct {
    ULONG Encapsulation;
    ULONG IpOptionsSupported : 2;
    ULONG TcpOptionsSupported : 2;
    ULONG TcpChecksum : 2;
    ULONG UdpChecksum : 2;
    ULONG IpChecksum : 2;
  } IPv4Receive;
  struct {
    ULONG Encapsulation;
    ULONG IpExtensionHeadersSupported : 2;
    ULONG TcpOptionsSupported : 2;
    ULONG TcpChecksum : 2;
    ULONG UdpChecksum : 2;
  } IPv6Transmit;
  struct {
    ULONG Encapsulation;
    ULONG IpExtensionHeadersSupported : 2;
    ULONG TcpOptionsSupported : 2;
    ULONG TcpChecksum : 2;
    ULONG UdpChecksum : 2;
  } IPv6Receive;
} NDIS_TCP_IP_CHECKSUM_OFFLOAD, *PNDIS_TCP_IP_CHECKSUM_OFFLOAD;

typedef struct _NDIS_IPSEC_OFFLOAD_V1 {
  struct {
    ULONG Encapsulation;
    ULONG AhEspCombined;
    ULONG TransportTunnelCombined;
    ULONG IPv4Options;
    ULONG Flags;
  } Supported;
  struct {
    ULONG Md5 : 2;
    ULONG Sha_1 : 2;
    ULONG Transport : 2;
    ULONG Tunnel : 2;
    ULONG Send : 2;
    ULONG Receive : 2;
  } IPv4AH;
  struct {
    ULONG Des : 2;
    ULONG Reserved : 2;
    ULONG TripleDes : 2;
    ULONG NullEsp : 2;
    ULONG Transport : 2;
    ULONG Tunnel : 2;
    ULONG Send : 2;
    ULONG Receive : 2;
  } IPv4ESP;
} NDIS_IPSEC_OFFLOAD_V1, *PNDIS_IPSEC_OFFLOAD_V1;

typedef struct _NDIS_TCP_LARGE_SEND_OFFLOAD_V1 {
  struct {
    ULONG Encapsulation;
    ULONG MaxOffLoadSize;
    ULONG MinSegmentCount;
    ULONG TcpOptions : 2;
    ULONG IpOptions : 2;
  } IPv4;
} NDIS_TCP_LARGE_SEND_OFFLOAD_V1, *PNDIS_TCP_LARGE_SEND_OFFLOAD_V1;

typedef struct _NDIS_TCP_LARGE_SEND_OFFLOAD_V2 {
  struct {
    ULONG Encapsulation;
    ULONG MaxOffLoadSize;
    ULONG MinSegmentCount;
  } IPv4;
  struct {
    ULONG Encapsulation;
    ULONG MaxOffLoadSize;
    ULONG MinSegmentCount;
    ULONG IpExtensionHeadersSupported : 2;
    ULONG TcpOptionsSupported : 2;
  } IPv6;
} NDIS_TCP_LARGE_SEND_OFFLOAD_V2, *PNDIS_TCP_LARGE_SEND_OFFLOAD_V2;

typedef struct _NDIS_TCP_RECV_SEG_COALESCE_OFFLOAD {
  struct {
    BOOLEAN Enabled;
  } IPv4;
  struct {
    BOOLEAN Enabled;
  } IPv6;
} NDIS_TCP_RECV_SEG_COALESCE_OFFLOAD, *PNDIS_TCP_RECV_SEG_COALESCE_OFFLOAD;

typedef struct _NDIS_OFFLOAD {
  NDIS_OBJECT_HEADER Header;
  NDIS_TCP_IP_CHECKSUM_OFFLOAD Checksum;
  NDIS_TCP_LARGE_SEND_OFFLOAD_V1 LsoV1;
  NDIS_IPSEC_OFFLOAD_V1 IPsecV1;
  NDIS_TCP_LARGE_SEND_OFFLOAD_V2 LsoV2;
  ULONG Flags;
  NDIS_TCP_RECV_SEG_COALESCE_OFFLOAD Rsc;
} NDIS_OFFLOAD, *PNDIS_OFFLOAD;

typedef struct _NDIS_OFFLOAD_ENCAPSULATION {
  NDIS_OBJECT_HEADER Header;
  struct {
    ULONG Enabled;
    ULONG EncapsulationType;
    ULONG HeaderSize;
  } IPv4;
  struct {
    ULONG Enabled;
    ULONG EncapsulationType;
    ULONG HeaderSize;
  } IPv6;
} NDIS_OFFLOAD_ENCAPSULATION, *PNDIS_OFFLOAD_ENCAPSULATION;

typedef struct _NDIS_OFFLOAD_PARAMETERS {
  NDIS_OBJECT_HEADER Header;
  UCHAR IPv4Checksum;
  UCHAR TCPIPv4Checksum;
  UCHAR UDPIPv4Checksum;
  UCHAR TCPIPv6Checksum;
  UCHAR UDPIPv6Checksum;
  UCHAR LsoV1;
  UCHAR IPsecV1;
  UCHAR LsoV2IPv4;
  UCHAR LsoV2IPv6;
  UCHAR TcpConnectionIPv4;
  UCHAR TcpConnectionIPv6;
  ULONG Flags;
  struct {
    UCHAR RscIPv4;
    UCHAR RscIPv6;
  };
} NDIS_OFFLOAD_PARAMETERS, *PNDIS_OFFLOAD_PARAMETERS;

typedef enum _NET_IF_MEDIA_CONNECT_STATE {
  MediaConnectStateUnknown,
  MediaConnectStateConnected,
  MediaConnectStateDisconnected
} NET_IF_MEDIA_CONNECT_STATE,
    *PNET_IF_MEDIA_CONNECT_STATE;
typedef NET_IF_MEDIA_CONNECT_STATE NDIS_MEDIA_CONNECT_STATE,
    *PNDIS_MEDIA_CONNECT_STATE;

typedef enum _NET_IF_MEDIA_DUPLEX_STATE {
  MediaDuplexStateUnknown,
  MediaDuplexStateHalf,
  MediaDuplexStateFull
} NET_IF_MEDIA_DUPLEX_STATE,
    *PNET_IF_MEDIA_DUPLEX_STATE;
typedef NET_IF_MEDIA_DUPLEX_STATE NDIS_MEDIA_DUPLEX_STATE,
    *PNDIS_MEDIA_DUPLEX_STATE;

typedef enum _NDIS_SUPPORTED_PAUSE_FUNCTIONS {
  NdisPauseFunctionsUnsupported,
  NdisPauseFunctionsSendOnly,
  NdisPauseFunctionsReceiveOnly,
  NdisPauseFunctionsSendAndReceive,
  NdisPauseFunctionsUnknown
} NDIS_SUPPORTED_PAUSE_FUNCTIONS,
    *PNDIS_SUPPORTED_PAUSE_FUNCTIONS;

typedef struct _NDIS_LINK_STATE {
  NDIS_OBJECT_HEADER Header;
  NDIS_MEDIA_CONNECT_STATE MediaConnectState;
  NDIS_MEDIA_DUPLEX_STATE MediaDuplexState;
  ULONG64 XmitLinkSpeed;
  ULONG64 RcvLinkSpeed;
  NDIS_SUPPORTED_PAUSE_FUNCTIONS PauseFunctions;
  ULONG AutoNegotiationFlags;
} NDIS_LINK_STATE, *PNDIS_LINK_STATE;

typedef NDIS_STATUS(MINIPORT_ADD_DEVICE)(NDIS_HANDLE NdisMiniportHandle,
                                         NDIS_HANDLE MiniportDriverContext);
typedef MINIPORT_ADD_DEVICE(*MINIPORT_ADD_DEVICE_HANDLER);

typedef struct _IO_STATUS_BLOCK {
  union {
    NTSTATUS Status;
    PVOID Pointer;
  };
  ULONG_PTR Information;
} IO_STATUS_BLOCK;

typedef struct _IRP {
  CSHORT Type;
  USHORT Size;
  struct _MDL *MdlAddress;
  ULONG Flags;
  union {
    struct _IRP *MasterIrp;
    LONG IrpCount;
    PVOID SystemBuffer;
  } AssociatedIrp;
  LIST_ENTRY ThreadListEntry;
  IO_STATUS_BLOCK IoStatus;
  BOOLEAN PendingReturned;
  CHAR StackCount;
  CHAR CurrentLocation;
  BOOLEAN Cancel;
  KIRQL CancelIrql;
  CCHAR ApcEnvironment;
  UCHAR AllocationFlags;
} IRP;
typedef struct _IRP *PIRP;

typedef NDIS_STATUS(MINIPORT_PNP_IRP)(NDIS_HANDLE MiniportAddDeviceContext,
                                      IRP *Irp);
typedef MINIPORT_PNP_IRP(*MINIPORT_PNP_IRP_HANDLER);
typedef MINIPORT_PNP_IRP(MINIPORT_START_DEVICE);
typedef MINIPORT_PNP_IRP(*MINIPORT_START_DEVICE_HANDLER);
typedef MINIPORT_PNP_IRP(MINIPORT_FILTER_RESOURCE_REQUIREMENTS);
typedef MINIPORT_PNP_IRP(*MINIPORT_FILTER_RESOURCE_REQUIREMENTS_HANDLER);

typedef VOID(MINIPORT_REMOVE_DEVICE)(NDIS_HANDLE MiniportAddDeviceContext);
typedef MINIPORT_REMOVE_DEVICE(*MINIPORT_REMOVE_DEVICE_HANDLER);

typedef struct _NDIS_MINIPORT_INIT_PARAMETERS {
  NDIS_OBJECT_HEADER Header;
  ULONG Flags;
  PNDIS_RESOURCE_LIST AllocatedResources;
  NDIS_HANDLE IMDeviceInstanceContext;
  NDIS_HANDLE MiniportAddDeviceContext;
} NDIS_MINIPORT_INIT_PARAMETERS, *PNDIS_MINIPORT_INIT_PARAMETERS;

typedef NDIS_STATUS(MINIPORT_INITIALIZE)(
    NDIS_HANDLE NdisMiniportHandle, NDIS_HANDLE MiniportDriverContext,
    PNDIS_MINIPORT_INIT_PARAMETERS MiniportInitParameters);
typedef MINIPORT_INITIALIZE(*MINIPORT_INITIALIZE_HANDLER);

typedef enum _NDIS_HALT_ACTION {
  NdisHaltDeviceDisabled,
  NdisHaltDeviceInstanceDeInitialized,
  NdisHaltDevicePoweredDown,
  NdisHaltDeviceSurpriseRemoved,
  NdisHaltDeviceFailed,
  NdisHaltDeviceInitializationFailed,
  NdisHaltDeviceStopped
} NDIS_HALT_ACTION,
    *PNDIS_HALT_ACTION;

typedef VOID(MINIPORT_HALT)(NDIS_HANDLE MiniportAdapterContext,
                            NDIS_HALT_ACTION HaltAction);
typedef MINIPORT_HALT(*MINIPORT_HALT_HANDLER);

typedef enum _NDIS_REQUEST_TYPE {
  NdisRequestQueryInformation,
  NdisRequestSetInformation,
  NdisRequestQueryStatistics,
  NdisRequestOpen,
  NdisRequestClose,
  NdisRequestSend,
  NdisRequestTransferData,
  NdisRequestReset,
  NdisRequestGeneric1,
  NdisRequestGeneric2,
  NdisRequestGeneric3,
  NdisRequestGeneric4,
  NdisRequestMethod,
} NDIS_REQUEST_TYPE,
    *PNDIS_REQUEST_TYPE;

#define NDIS_OID_REQUEST_NDIS_RESERVED_SIZE 16
typedef struct _NDIS_OID_REQUEST {
  NDIS_OBJECT_HEADER Header;
  NDIS_REQUEST_TYPE RequestType;
  NDIS_PORT_NUMBER PortNumber;
  UINT Timeout;
  PVOID RequestId;
  NDIS_HANDLE RequestHandle;
  union _REQUEST_DATA {
    struct _QUERY {
      NDIS_OID Oid;
      PVOID InformationBuffer;
      UINT InformationBufferLength;
      UINT BytesWritten;
      UINT BytesNeeded;
    } QUERY_INFORMATION;
    struct _SET {
      NDIS_OID Oid;
      PVOID InformationBuffer;
      UINT InformationBufferLength;
      UINT BytesRead;
      UINT BytesNeeded;
    } SET_INFORMATION;
    struct _METHOD {
      NDIS_OID Oid;
      PVOID InformationBuffer;
      ULONG InputBufferLength;
      ULONG OutputBufferLength;
      ULONG MethodId;
      UINT BytesWritten;
      UINT BytesRead;
      UINT BytesNeeded;
    } METHOD_INFORMATION;
  } DATA;
  UCHAR NdisReserved[NDIS_OID_REQUEST_NDIS_RESERVED_SIZE * sizeof(PVOID)];
  UCHAR MiniportReserved[2 * sizeof(PVOID)];
  UCHAR SourceReserved[2 * sizeof(PVOID)];
  UCHAR SupportedRevision;
  UCHAR Reserved1;
  USHORT Reserved2;
} NDIS_OID_REQUEST, *PNDIS_OID_REQUEST;

typedef NDIS_STATUS(MINIPORT_OID_REQUEST)(NDIS_HANDLE MiniportAdapterContext,
                                          PNDIS_OID_REQUEST OidRequest);
typedef MINIPORT_OID_REQUEST(*MINIPORT_OID_REQUEST_HANDLER);

typedef VOID(MINIPORT_CANCEL_OID_REQUEST)(NDIS_HANDLE MiniportAdapterContext,
                                          PVOID RequestId);
typedef MINIPORT_CANCEL_OID_REQUEST(*MINIPORT_CANCEL_OID_REQUEST_HANDLER);

typedef NDIS_STATUS(MINIPORT_DIRECT_OID_REQUEST)(
    NDIS_HANDLE MiniportAdapterContext, PNDIS_OID_REQUEST OidRequest);
typedef MINIPORT_DIRECT_OID_REQUEST(*MINIPORT_DIRECT_OID_REQUEST_HANDLER);

typedef VOID(MINIPORT_CANCEL_DIRECT_OID_REQUEST)(
    NDIS_HANDLE MiniportAdapterContext, PVOID RequestId);
typedef MINIPORT_CANCEL_DIRECT_OID_REQUEST(
    *MINIPORT_CANCEL_DIRECT_OID_REQUEST_HANDLER);

typedef VOID(MINIPORT_UNLOAD)(PDRIVER_OBJECT DriverObject);
typedef MINIPORT_UNLOAD(*MINIPORT_DRIVER_UNLOAD);

typedef struct _NDIS_MINIPORT_PAUSE_PARAMETERS {
  NDIS_OBJECT_HEADER Header;
  ULONG Flags;
  ULONG PauseReason;
} NDIS_MINIPORT_PAUSE_PARAMETERS, *PNDIS_MINIPORT_PAUSE_PARAMETERS;

typedef NDIS_STATUS(MINIPORT_PAUSE)(
    NDIS_HANDLE MiniportAdapterContext,
    PNDIS_MINIPORT_PAUSE_PARAMETERS PauseParameters);
typedef MINIPORT_PAUSE(*MINIPORT_PAUSE_HANDLER);

typedef struct _NDIS_RESTART_ATTRIBUTES NDIS_RESTART_ATTRIBUTES,
    *PNDIS_RESTART_ATTRIBUTES;

typedef struct _NDIS_RESTART_ATTRIBUTES {
  PNDIS_RESTART_ATTRIBUTES Next;
  NDIS_OID Oid;
  ULONG DataLength;
  UCHAR Data[1];
} NDIS_RESTART_ATTRIBUTES, *PNDIS_RESTART_ATTRIBUTES;

typedef struct _NDIS_MINIPORT_RESTART_PARAMETERS {
  NDIS_OBJECT_HEADER Header;
  PNDIS_RESTART_ATTRIBUTES RestartAttributes;
  ULONG Flags;
} NDIS_MINIPORT_RESTART_PARAMETERS, *PNDIS_MINIPORT_RESTART_PARAMETERS;

typedef NDIS_STATUS(MINIPORT_RESTART)(
    NDIS_HANDLE MiniportAdapterContext,
    PNDIS_MINIPORT_RESTART_PARAMETERS RestartParameters);
typedef MINIPORT_RESTART(*MINIPORT_RESTART_HANDLER);

typedef enum _NDIS_SHUTDOWN_ACTION {
  NdisShutdownPowerOff,
  NdisShutdownBugCheck
} NDIS_SHUTDOWN_ACTION,
    PNDIS_SHUTDOWN_ACTION;

typedef VOID(MINIPORT_SHUTDOWN)(NDIS_HANDLE MiniportAdapterContext,
                                NDIS_SHUTDOWN_ACTION ShutdownAction);
typedef MINIPORT_SHUTDOWN(*MINIPORT_SHUTDOWN_HANDLER);

typedef enum _NDIS_DEVICE_PNP_EVENT {
  NdisDevicePnPEventQueryRemoved,
  NdisDevicePnPEventRemoved,
  NdisDevicePnPEventSurpriseRemoved,
  NdisDevicePnPEventQueryStopped,
  NdisDevicePnPEventStopped,
  NdisDevicePnPEventPowerProfileChanged,
  NdisDevicePnPEventFilterListChanged,
  NdisDevicePnPEventMaximum
} NDIS_DEVICE_PNP_EVENT,
    *PNDIS_DEVICE_PNP_EVENT;

typedef struct _NET_DEVICE_PNP_EVENT {
  NDIS_OBJECT_HEADER Header;
  NDIS_PORT_NUMBER PortNumber;
  NDIS_DEVICE_PNP_EVENT DevicePnPEvent;
  PVOID InformationBuffer;
  ULONG InformationBufferLength;
  UCHAR NdisReserved[2 * sizeof(PVOID)];
} NET_DEVICE_PNP_EVENT, *PNET_DEVICE_PNP_EVENT;

typedef VOID(MINIPORT_DEVICE_PNP_EVENT_NOTIFY)(
    NDIS_HANDLE MiniportAdapterContext,
    PNET_DEVICE_PNP_EVENT NetDevicePnPEvent);
typedef MINIPORT_DEVICE_PNP_EVENT_NOTIFY(
    *MINIPORT_DEVICE_PNP_EVENT_NOTIFY_HANDLER);

typedef VOID(MINIPORT_SEND_NET_BUFFER_LISTS)(NDIS_HANDLE MiniportAdapterContext,
                                             PNET_BUFFER_LIST NetBufferList,
                                             NDIS_PORT_NUMBER PortNumber,
                                             ULONG SendFlags);
typedef MINIPORT_SEND_NET_BUFFER_LISTS(*MINIPORT_SEND_NET_BUFFER_LISTS_HANDLER);

typedef VOID(MINIPORT_CANCEL_SEND)(NDIS_HANDLE MiniportAdapterContext,
                                   PVOID CancelId);
typedef MINIPORT_CANCEL_SEND(*MINIPORT_CANCEL_SEND_HANDLER);

typedef VOID(MINIPORT_RETURN_NET_BUFFER_LISTS)(
    NDIS_HANDLE MiniportAdapterContext, PNET_BUFFER_LIST NetBufferLists,
    ULONG ReturnFlags);
typedef MINIPORT_RETURN_NET_BUFFER_LISTS(
    *MINIPORT_RETURN_NET_BUFFER_LISTS_HANDLER);

typedef enum _NDIS_DEVICE_POWER_STATE {
  NdisDeviceStateUnspecified = 0,
  NdisDeviceStateD0,
  NdisDeviceStateD1,
  NdisDeviceStateD2,
  NdisDeviceStateD3,
  NdisDeviceStateMaximum
} NDIS_DEVICE_POWER_STATE,
    *PNDIS_DEVICE_POWER_STATE;

typedef struct _NDIS_PM_WAKE_UP_CAPABILITIES {
  NDIS_DEVICE_POWER_STATE MinMagicPacketWakeUp;
  NDIS_DEVICE_POWER_STATE MinPatternWakeUp;
  NDIS_DEVICE_POWER_STATE MinLinkChangeWakeUp;
} NDIS_PM_WAKE_UP_CAPABILITIES, *PNDIS_PM_WAKE_UP_CAPABILITIES;

typedef struct _NDIS_PNP_CAPABILITIES {
  ULONG Flags;
  NDIS_PM_WAKE_UP_CAPABILITIES WakeUpCapabilities;
} NDIS_PNP_CAPABILITIES, *PNDIS_PNP_CAPABILITIES;

typedef struct _NDIS_MINIPORT_ADD_DEVICE_REGISTRATION_ATTRIBUTES {
  NDIS_OBJECT_HEADER Header;
  NDIS_HANDLE MiniportAddDeviceContext;
  ULONG Flags;
} NDIS_MINIPORT_ADD_DEVICE_REGISTRATION_ATTRIBUTES,
    *PNDIS_MINIPORT_ADD_DEVICE_REGISTRATION_ATTRIBUTES;

typedef enum _NDIS_INTERFACE_TYPE {
  NdisInterfacePci,
  NdisMaximumInterfaceType
} NDIS_INTERFACE_TYPE,
    *PNDIS_INTERFACE_TYPE;

typedef struct _NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES {
  NDIS_OBJECT_HEADER Header;
  NDIS_HANDLE MiniportAdapterContext;
  ULONG AttributeFlags;
  UINT CheckForHangTimeInSeconds;
  NDIS_INTERFACE_TYPE InterfaceType;
} NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES,
    *PNDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES;

typedef enum _NDIS_MEDIUM {
  NdisMedium802_3,
  NdisMediumMax
} NDIS_MEDIUM,
    *PNDIS_MEDIUM;

typedef enum _NDIS_PHYSICAL_MEDIUM {
  NdisPhysicalMediumUnspecified,
  NdisPhysicalMedium802_3,
  NdisPhysicalMediumMax
} NDIS_PHYSICAL_MEDIUM,
    *PNDIS_PHYSICAL_MEDIUM;

#define NDIS_MAX_PHYS_ADDRESS_LENGTH 32

typedef enum _NET_IF_ACCESS_TYPE {
  NET_IF_ACCESS_LOOPBACK = 1,
  NET_IF_ACCESS_BROADCAST = 2,
  NET_IF_ACCESS_POINT_TO_POINT = 3,
  NET_IF_ACCESS_POINT_TO_MULTI_POINT = 4,
  NET_IF_ACCESS_MAXIMUM = 5
} NET_IF_ACCESS_TYPE,
    *PNET_IF_ACCESS_TYPE;

typedef enum _NET_IF_DIRECTION_TYPE {
  NET_IF_DIRECTION_SENDRECEIVE,
  NET_IF_DIRECTION_SENDONLY,
  NET_IF_DIRECTION_RECEIVEONLY,
  NET_IF_DIRECTION_MAXIMUM
} NET_IF_DIRECTION_TYPE,
    *PNET_IF_DIRECTION_TYPE;

typedef enum _NET_IF_CONNECTION_TYPE {
  NET_IF_CONNECTION_DEDICATED = 1,
  NET_IF_CONNECTION_PASSIVE = 2,
  NET_IF_CONNECTION_DEMAND = 3,
  NET_IF_CONNECTION_MAXIMUM = 4
} NET_IF_CONNECTION_TYPE,
    *PNET_IF_CONNECTION_TYPE;

typedef UINT16 NET_IFTYPE, *PNET_IFTYPE;

typedef struct _NDIS_PM_CAPABILITIES {
  NDIS_OBJECT_HEADER Header;
  ULONG Flags;
  ULONG SupportedWoLPacketPatterns;
  ULONG NumTotalWoLPatterns;
  ULONG MaxWoLPatternSize;
  ULONG MaxWoLPatternOffset;
  ULONG MaxWoLPacketSaveBuffer;
  ULONG SupportedProtocolOffloads;
  ULONG NumArpOffloadIPv4Addresses;
  ULONG NumNSOffloadIPv6Addresses;
  NDIS_DEVICE_POWER_STATE MinMagicPacketWakeUp;
  NDIS_DEVICE_POWER_STATE MinPatternWakeUp;
  NDIS_DEVICE_POWER_STATE MinLinkChangeWakeUp;
} NDIS_PM_CAPABILITIES, *PNDIS_PM_CAPABILITIES;

typedef struct _NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES {
  NDIS_OBJECT_HEADER Header;
  ULONG Flags;
  NDIS_MEDIUM MediaType;
  NDIS_PHYSICAL_MEDIUM PhysicalMediumType;
  ULONG MtuSize;
  ULONG64 MaxXmitLinkSpeed;
  ULONG64 XmitLinkSpeed;
  ULONG64 MaxRcvLinkSpeed;
  ULONG64 RcvLinkSpeed;
  NDIS_MEDIA_CONNECT_STATE MediaConnectState;
  NDIS_MEDIA_DUPLEX_STATE MediaDuplexState;
  ULONG LookaheadSize;
  PNDIS_PNP_CAPABILITIES PowerManagementCapabilities;
  ULONG MacOptions;
  ULONG SupportedPacketFilters;
  ULONG MaxMulticastListSize;
  USHORT MacAddressLength;
  UCHAR PermanentMacAddress[NDIS_MAX_PHYS_ADDRESS_LENGTH];
  UCHAR CurrentMacAddress[NDIS_MAX_PHYS_ADDRESS_LENGTH];
  PNDIS_RECEIVE_SCALE_CAPABILITIES RecvScaleCapabilities;
  NET_IF_ACCESS_TYPE AccessType;
  NET_IF_DIRECTION_TYPE DirectionType;
  NET_IF_CONNECTION_TYPE ConnectionType;
  NET_IFTYPE IfType;
  BOOLEAN IfConnectorPresent;
  ULONG SupportedStatistics;
  ULONG SupportedPauseFunctions;
  ULONG DataBackFillSize;
  ULONG ContextBackFillSize;
  PNDIS_OID SupportedOidList;
  ULONG SupportedOidListLength;
  ULONG AutoNegotiationFlags;
  PNDIS_PM_CAPABILITIES PowerManagementCapabilitiesEx;
} NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES,
    *PNDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES;

typedef struct _NDIS_TCP_CONNECTION_OFFLOAD {
  NDIS_OBJECT_HEADER Header;
  ULONG Encapsulation;
  ULONG SupportIPv4 : 2;
  ULONG SupportIPv6 : 2;
  ULONG SupportIPv6ExtensionHeaders : 2;
  ULONG SupportSack : 2;
  ULONG CongestionAlgorithm : 4;
  ULONG TcpConnectionOffloadCapacity;
  ULONG Flags;
} NDIS_TCP_CONNECTION_OFFLOAD, *PNDIS_TCP_CONNECTION_OFFLOAD;

typedef struct _NDIS_MINIPORT_ADAPTER_OFFLOAD_ATTRIBUTES {
  NDIS_OBJECT_HEADER Header;
  PNDIS_OFFLOAD DefaultOffloadConfiguration;
  PNDIS_OFFLOAD HardwareOffloadCapabilities;
  PNDIS_TCP_CONNECTION_OFFLOAD DefaultTcpConnectionOffloadConfiguration;
  PNDIS_TCP_CONNECTION_OFFLOAD TcpConnectionOffloadHardwareCapabilities;
} NDIS_MINIPORT_ADAPTER_OFFLOAD_ATTRIBUTES,
    *PNDIS_MINIPORT_ADAPTER_OFFLOAD_ATTRIBUTES;

typedef union _NDIS_MINIPORT_ADAPTER_ATTRIBUTES {
  NDIS_OBJECT_HEADER Header;
  NDIS_MINIPORT_ADD_DEVICE_REGISTRATION_ATTRIBUTES
  AddDeviceRegistrationAttributes;
  NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES RegistrationAttributes;
  NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES GeneralAttributes;
  NDIS_MINIPORT_ADAPTER_OFFLOAD_ATTRIBUTES OffloadAttributes;
} NDIS_MINIPORT_ADAPTER_ATTRIBUTES, *PNDIS_MINIPORT_ADAPTER_ATTRIBUTES;

typedef enum _INTERFACE_TYPE {
  InterfaceTypeUndefined = -1,
  Internal,
  Isa,
  Eisa,
  MicroChannel,
  TurboChannel,
  PCIBus,
  VMEBus,
  NuBus,
  PCMCIABus,
  CBus,
  MPIBus,
  MPSABus,
  ProcessorInternal,
  InternalPowerBus,
  PNPISABus,
  PNPBus,
  MaximumInterfaceType
} INTERFACE_TYPE,
    *PINTERFACE_TYPE;

typedef enum _IRQ_DEVICE_POLICY {
  IrqPolicyMachineDefault = 0,
  IrqPolicyAllCloseProcessors,
  IrqPolicyOneCloseProcessor,
  IrqPolicyAllProcessorsInMachine,
  IrqPolicySpecifiedProcessors,
  IrqPolicySpreadMessagesAcrossAllProcessors
} IRQ_DEVICE_POLICY,
    *PIRQ_DEVICE_POLICY;

typedef enum _IRQ_PRIORITY {
  IrqPriorityUndefined = 0,
  IrqPriorityLow,
  IrqPriorityNormal,
  IrqPriorityHigh
} IRQ_PRIORITY,
    *PIRQ_PRIORITY;

typedef struct _IO_RESOURCE_DESCRIPTOR {
  UCHAR Option;
  UCHAR Type;
  UCHAR ShareDisposition;
  UCHAR Spare1;
  USHORT Flags;
  USHORT Spare2;
  union {
    struct {
      ULONG Length;
      ULONG Alignment;
      PHYSICAL_ADDRESS MinimumAddress;
      PHYSICAL_ADDRESS MaximumAddress;
    } Port;
    struct {
      ULONG Length;
      ULONG Alignment;
      PHYSICAL_ADDRESS MinimumAddress;
      PHYSICAL_ADDRESS MaximumAddress;
    } Memory;
    struct {
      ULONG MinimumVector;
      ULONG MaximumVector;
      IRQ_DEVICE_POLICY AffinityPolicy;
      USHORT Group;
      IRQ_PRIORITY PriorityPolicy;
      KAFFINITY TargetedProcessors;
    } Interrupt;
    struct {
      ULONG MinimumChannel;
      ULONG MaximumChannel;
    } Dma;
    struct {
      ULONG RequestLine;
      ULONG Reserved;
      ULONG Channel;
      ULONG TransferWidth;
    } DmaV3;
    struct {
      ULONG Length;
      ULONG Alignment;
      PHYSICAL_ADDRESS MinimumAddress;
      PHYSICAL_ADDRESS MaximumAddress;
    } Generic;
    struct {
      ULONG Data[3];
    } DevicePrivate;
    struct {
      ULONG Length;
      ULONG MinBusNumber;
      ULONG MaxBusNumber;
      ULONG Reserved;
    } BusNumber;
    struct {
      ULONG Priority;
      ULONG Reserved1;
      ULONG Reserved2;
    } ConfigData;
    struct {
      ULONG Length40;
      ULONG Alignment40;
      PHYSICAL_ADDRESS MinimumAddress;
      PHYSICAL_ADDRESS MaximumAddress;
    } Memory40;
    struct {
      ULONG Length48;
      ULONG Alignment48;
      PHYSICAL_ADDRESS MinimumAddress;
      PHYSICAL_ADDRESS MaximumAddress;
    } Memory48;
    struct {
      ULONG Length64;
      ULONG Alignment64;
      PHYSICAL_ADDRESS MinimumAddress;
      PHYSICAL_ADDRESS MaximumAddress;
    } Memory64;
    struct {
      UCHAR Class;
      UCHAR Type;
      UCHAR Reserved1;
      UCHAR Reserved2;
      ULONG IdLowPart;
      ULONG IdHighPart;
    } Connection;
  } u;
} IO_RESOURCE_DESCRIPTOR, *PIO_RESOURCE_DESCRIPTOR;

typedef struct _IO_RESOURCE_LIST {
  USHORT Version;
  USHORT Revision;
  ULONG Count;
  IO_RESOURCE_DESCRIPTOR Descriptors[1];
} IO_RESOURCE_LIST, *PIO_RESOURCE_LIST;

typedef struct _IO_RESOURCE_REQUIREMENTS_LIST {
  ULONG ListSize;
  INTERFACE_TYPE InterfaceType;
  ULONG BusNumber;
  ULONG SlotNumber;
  ULONG Reserved[3];
  ULONG AlternativeLists;
  IO_RESOURCE_LIST List[1];
} IO_RESOURCE_REQUIREMENTS_LIST, *PIO_RESOURCE_REQUIREMENTS_LIST;

typedef struct _NDIS_RECEIVE_THROTTLE_PARAMETERS {
  ULONG MaxNblsToIndicate;
  ULONG MoreNblsPending : 1;
} NDIS_RECEIVE_THROTTLE_PARAMETERS, *PNDIS_RECEIVE_THROTTLE_PARAMETERS;

#define NDIS_INDICATE_ALL_NBLS (~0u)

typedef NDIS_STATUS(SET_OPTIONS)(NDIS_HANDLE NdisDriverHandle,
                                 NDIS_HANDLE DriverContext);
typedef SET_OPTIONS(*SET_OPTIONS_HANDLER);

typedef BOOLEAN(MINIPORT_CHECK_FOR_HANG)(NDIS_HANDLE MiniportAdapterContext);
typedef MINIPORT_CHECK_FOR_HANG(*MINIPORT_CHECK_FOR_HANG_HANDLER);

typedef NDIS_STATUS(MINIPORT_RESET)(NDIS_HANDLE MiniportAdapterContext,
                                    PBOOLEAN AddressingReset);
typedef MINIPORT_RESET(*MINIPORT_RESET_HANDLER);

typedef struct _NDIS_MINIPORT_DRIVER_CHARACTERISTICS {
  NDIS_OBJECT_HEADER Header;
  UCHAR MajorNdisVersion;
  UCHAR MinorNdisVersion;
  UCHAR MajorDriverVersion;
  UCHAR MinorDriverVersion;
  ULONG Flags;
  SET_OPTIONS_HANDLER SetOptionsHandler;
  MINIPORT_INITIALIZE_HANDLER InitializeHandlerEx;
  MINIPORT_HALT_HANDLER HaltHandlerEx;
  MINIPORT_DRIVER_UNLOAD UnloadHandler;
  MINIPORT_PAUSE_HANDLER PauseHandler;
  MINIPORT_RESTART_HANDLER RestartHandler;
  MINIPORT_OID_REQUEST_HANDLER OidRequestHandler;
  MINIPORT_SEND_NET_BUFFER_LISTS_HANDLER SendNetBufferListsHandler;
  MINIPORT_RETURN_NET_BUFFER_LISTS_HANDLER ReturnNetBufferListsHandler;
  MINIPORT_CANCEL_SEND_HANDLER CancelSendHandler;
  MINIPORT_CHECK_FOR_HANG_HANDLER CheckForHangHandlerEx;
  MINIPORT_RESET_HANDLER ResetHandlerEx;
  MINIPORT_DEVICE_PNP_EVENT_NOTIFY_HANDLER DevicePnPEventNotifyHandler;
  MINIPORT_SHUTDOWN_HANDLER ShutdownHandlerEx;
  MINIPORT_CANCEL_OID_REQUEST_HANDLER CancelOidRequestHandler;
  MINIPORT_DIRECT_OID_REQUEST_HANDLER DirectOidRequestHandler;
  MINIPORT_CANCEL_DIRECT_OID_REQUEST_HANDLER CancelDirectOidRequestHandler;
} NDIS_MINIPORT_DRIVER_CHARACTERISTICS, *PNDIS_MINIPORT_DRIVER_CHARACTERISTICS;

typedef struct _NDIS_DRIVER_OPTIONAL_HANDLERS {
  NDIS_OBJECT_HEADER Header;
} NDIS_DRIVER_OPTIONAL_HANDLERS, *PNDIS_DRIVER_OPTIONAL_HANDLERS;

typedef struct _NDIS_MINIPORT_PNP_CHARACTERISTICS {
  NDIS_OBJECT_HEADER Header;
  MINIPORT_ADD_DEVICE_HANDLER MiniportAddDeviceHandler;
  MINIPORT_REMOVE_DEVICE_HANDLER MiniportRemoveDeviceHandler;
  MINIPORT_FILTER_RESOURCE_REQUIREMENTS_HANDLER
  MiniportFilterResourceRequirementsHandler;
  MINIPORT_START_DEVICE_HANDLER MiniportStartDeviceHandler;
  ULONG Flags;
} NDIS_MINIPORT_PNP_CHARACTERISTICS, *PNDIS_MINIPORT_PNP_CHARACTERISTICS;

typedef enum _NDIS_INTERRUPT_MODERATION {
  NdisInterruptModerationUnknown,
  NdisInterruptModerationNotSupported,
  NdisInterruptModerationEnabled,
  NdisInterruptModerationDisabled
} NDIS_INTERRUPT_MODERATION,
    *PNDIS_INTERRUPT_MODERATION;

#define NDIS_INTERRUPT_MODERATION_CHANGE_NEEDS_RESET 0x00000001
#define NDIS_INTERRUPT_MODERATION_CHANGE_NEEDS_REINITIALIZE 0x00000002

typedef struct _NDIS_INTERRUPT_MODERATION_PARAMETERS {
  NDIS_OBJECT_HEADER Header;
  ULONG Flags;
  NDIS_INTERRUPT_MODERATION InterruptModeration;
} NDIS_INTERRUPT_MODERATION_PARAMETERS, *PNDIS_INTERRUPT_MODERATION_PARAMETERS;

typedef enum _NDIS_HARDWARE_STATUS {
  NdisHardwareStatusReady,
  NdisHardwareStatusInitializing,
  NdisHardwareStatusReset,
  NdisHardwareStatusClosing,
  NdisHardwareStatusNotReady
} NDIS_HARDWARE_STATUS,
    *PNDIS_HARDWARE_STATUS;

typedef struct _NDIS_LINK_PARAMETERS {
  NDIS_OBJECT_HEADER Header;
  NDIS_MEDIA_DUPLEX_STATE MediaDuplexState;
  ULONG64 XmitLinkSpeed;
  ULONG64 RcvLinkSpeed;
  NDIS_SUPPORTED_PAUSE_FUNCTIONS PauseFunctions;
  ULONG AutoNegotiationFlags;
} NDIS_LINK_PARAMETERS, *PNDIS_LINK_PARAMETERS;

typedef PVOID PALLOCATE_FUNCTION, PFREE_FUNCTION;
typedef struct _NPAGED_LOOKASIDE_LIST {
  ULONG Size;
} NPAGED_LOOKASIDE_LIST, *PNPAGED_LOOKASIDE_LIST;

typedef BOOLEAN(MINIPORT_SYNCHRONIZE_INTERRUPT)(NDIS_HANDLE SynchronizeContext);
typedef MINIPORT_SYNCHRONIZE_INTERRUPT(*MINIPORT_SYNCHRONIZE_INTERRUPT_HANDLER);
typedef MINIPORT_SYNCHRONIZE_INTERRUPT(MINIPORT_SYNCHRONIZE_MESSAGE_INTERRUPT);
typedef MINIPORT_SYNCHRONIZE_MESSAGE_INTERRUPT(
    *MINIPORT_SYNCHRONIZE_MSI_INTERRUPT_HANDLER);

typedef struct _NDIS_RSS_PROCESSOR_INFO {
  NDIS_OBJECT_HEADER Header;
  ULONG Flags;
  PROCESSOR_NUMBER RssBaseProcessor;
  ULONG MaxNumRssProcessors;
  USHORT PreferredNumaNode;
  ULONG RssProcessorArrayOffset;
  ULONG RssProcessorCount;
  ULONG RssProcessorEntrySize;
} NDIS_RSS_PROCESSOR_INFO, *PNDIS_RSS_PROCESSOR_INFO;

typedef struct _NDIS_RSS_PROCESSOR {
  PROCESSOR_NUMBER ProcNum;
  USHORT PreferenceIndex;
  USHORT Reserved;
} NDIS_RSS_PROCESSOR, *PNDIS_RSS_PROCESSOR;

typedef enum _CM_SHARE_DISPOSITION {
  CmResourceShareUndetermined = 0,
  CmResourceShareDeviceExclusive,
  CmResourceShareDriverExclusive,
  CmResourceShareShared
} CM_SHARE_DISPOSITION;

#define CM_RESOURCE_INTERRUPT_MESSAGE_TOKEN ((ULONG)-2)

typedef enum _NDIS_MSIX_TABLE_CONFIG {
  NdisMSIXTableConfigSetTableEntry,
  NdisMSIXTableConfigMaskTableEntry,
  NdisMSIXTableConfigUnmaskTableEntry,
  NdisMSIXTableConfigMax
} NDIS_MSIX_TABLE_OPERATION,
    *PNDIS_MSIX_TABLE_OPERATION;

typedef struct _NDIS_MSIX_CONFIG_PARAMETERS {
  NDIS_OBJECT_HEADER Header;
  NDIS_MSIX_TABLE_OPERATION ConfigOperation;
  ULONG TableEntry;
  ULONG MessageNumber;
} NDIS_MSIX_CONFIG_PARAMETERS, *PNDIS_MSIX_CONFIG_PARAMETERS;

typedef VOID(NDIS_TIMER_FUNCTION)(PVOID SystemSpecific1, PVOID FunctionContext,
                                  PVOID SystemSpecific2, PVOID SystemSpecific3);
typedef NDIS_TIMER_FUNCTION(*PNDIS_TIMER_FUNCTION);

typedef struct _NDIS_TIMER_CHARACTERISTICS {
  NDIS_OBJECT_HEADER Header;
  ULONG AllocationTag;
  PNDIS_TIMER_FUNCTION TimerFunction;
  PVOID FunctionContext;
} NDIS_TIMER_CHARACTERISTICS, *PNDIS_TIMER_CHARACTERISTICS;

typedef struct _OSVERSIONINFOW {
  ULONG dwOSVersionInfoSize;
  ULONG dwMajorVersion;
  ULONG dwMinorVersion;
  ULONG dwBuildNumber;
  ULONG dwPlatformId;
  WCHAR szCSDVersion[128];
} OSVERSIONINFOW, *POSVERSIONINFOW, *LPOSVERSIONINFOW, RTL_OSVERSIONINFOW,
    *PRTL_OSVERSIONINFOW;

typedef VOID(NDIS_IO_WORKITEM_FUNCTION)(PVOID WorkItemContext,
                                        NDIS_HANDLE NdisIoWorkItemHandle);
typedef NDIS_IO_WORKITEM_FUNCTION(*NDIS_IO_WORKITEM_ROUTINE);

#define LOOKASIDE_MINIMUM_BLOCK_SIZE 0

#define NDIS_LINK_SPEED_UNKNOWN ((ULONG64)(-1))

#define NDIS_TCP_LARGE_SEND_OFFLOAD_V1_TYPE 0
#define NDIS_TCP_LARGE_SEND_OFFLOAD_V2_TYPE 1

#define NDIS_TCP_LARGE_SEND_OFFLOAD_IPv4 0
#define NDIS_TCP_LARGE_SEND_OFFLOAD_IPv6 1

#define NDIS_OFFLOAD_NOT_SUPPORTED 0
#define NDIS_OFFLOAD_SUPPORTED 1

#define NDIS_OFFLOAD_PARAMETERS_NO_CHANGE 0

#define NDIS_OFFLOAD_SET_NO_CHANGE 0
#define NDIS_OFFLOAD_SET_ON 1
#define NDIS_OFFLOAD_SET_OFF 2

#define NDIS_OFFLOAD_PARAMETERS_TX_RX_DISABLED 1
#define NDIS_OFFLOAD_PARAMETERS_TX_ENABLED_RX_DISABLED 2
#define NDIS_OFFLOAD_PARAMETERS_RX_ENABLED_TX_DISABLED 3
#define NDIS_OFFLOAD_PARAMETERS_TX_RX_ENABLED 4

#define NDIS_OFFLOAD_PARAMETERS_LSOV1_DISABLED 1
#define NDIS_OFFLOAD_PARAMETERS_LSOV1_ENABLED 2
#define NDIS_OFFLOAD_PARAMETERS_LSOV2_DISABLED 1
#define NDIS_OFFLOAD_PARAMETERS_LSOV2_ENABLED 2

#define NDIS_OFFLOAD_PARAMETERS_RSC_DISABLED 1
#define NDIS_OFFLOAD_PARAMETERS_RSC_ENABLED 2

#define NDIS_ENCAPSULATION_NOT_SUPPORTED 0x00000000
#define NDIS_ENCAPSULATION_IEEE_802_3 0x00000002

#define CmResourceTypeInterrupt 2
#define CmResourceTypeMemory 3

#define CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE 0x0
#define CM_RESOURCE_INTERRUPT_LATCHED 0x01
#define CM_RESOURCE_INTERRUPT_MESSAGE 0x02
#define CM_RESOURCE_INTERRUPT_POLICY_INCLUDED 0x04
#define CM_RESOURCE_INTERRUPT_SECONDARY_INTERRUPT 0x10
#define CM_RESOURCE_INTERRUPT_WAKE_HINT 0x20

#define NDIS_SG_LIST_WRITE_TO_DEVICE 0x000000001
#define NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL 0x00000001

#define NDIS_STATUS_SUCCESS ((NDIS_STATUS)0L)
#define NDIS_STATUS_PENDING ((NDIS_STATUS)0x00000103L)
#define NDIS_STATUS_NOT_ACCEPTED ((NDIS_STATUS)0x00010003L)
#define NDIS_STATUS_LINK_STATE ((NDIS_STATUS)0x40010017L)
#define NDIS_STATUS_TASK_OFFLOAD_CURRENT_CONFIG ((NDIS_STATUS)0x40020006L)
#define NDIS_STATUS_BUFFER_OVERFLOW ((NDIS_STATUS)0x80000005L)
#define NDIS_STATUS_HARD_ERRORS ((NDIS_STATUS)0x80010004L)
#define NDIS_STATUS_FAILURE ((NDIS_STATUS)0xC0000001L)
#define NDIS_STATUS_INVALID_PARAMETER ((NDIS_STATUS)0xC000000DL)
#define NDIS_STATUS_RESOURCES ((NDIS_STATUS)0xC000009AL)
#define NDIS_STATUS_NOT_SUPPORTED ((NDIS_STATUS)0xC00000BBL)
#define NDIS_STATUS_RESET_IN_PROGRESS ((NDIS_STATUS)0xC001000DL)
#define NDIS_STATUS_INVALID_LENGTH ((NDIS_STATUS)0xC0010014L)
#define NDIS_STATUS_INVALID_DATA ((NDIS_STATUS)0xC0010015L)
#define NDIS_STATUS_BUFFER_TOO_SHORT ((NDIS_STATUS)0xC0010016L)
#define NDIS_STATUS_RESOURCE_CONFLICT ((NDIS_STATUS)0xC001001EL)
#define NDIS_STATUS_PAUSED ((NDIS_STATUS)0xC023002AL)
#define NDIS_STATUS_LOW_POWER_STATE ((NDIS_STATUS)0xC023002FL)

#define STATUS_SUCCESS NDIS_STATUS_SUCCESS
#define STATUS_BUFFER_OVERFLOW NDIS_STATUS_BUFFER_OVERFLOW
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#define STATUS_INVALID_PARAMETER NDIS_STATUS_INVALID_PARAMETER
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xC0000034L)
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#define STATUS_NDIS_NOT_SUPPORTED ((NTSTATUS)0xC02300BBL)

#define NDIS_OBJECT_TYPE_DEFAULT 0x80  // Used when the object type is implied.
#define NDIS_OBJECT_TYPE_SG_DMA_DESCRIPTION 0x83
#define NDIS_OBJECT_TYPE_MINIPORT_INTERRUPT 0x84
#define NDIS_OBJECT_TYPE_RSS_CAPABILITIES 0x88
#define NDIS_OBJECT_TYPE_MINIPORT_DRIVER_CHARACTERISTICS 0x8A
#define NDIS_OBJECT_TYPE_MINIPORT_PNP_CHARACTERISTICS 0x9
#define NDIS_OBJECT_TYPE_TIMER_CHARACTERISTICS 0x97
#define NDIS_OBJECT_TYPE_STATUS_INDICATION 0x98
#define NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES 0x9E
#define NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES 0x9F
#define NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_OFFLOAD_ATTRIBUTES 0xA0
#define NDIS_OBJECT_TYPE_MINIPORT_ADD_DEVICE_REGISTRATION_ATTRIBUTES 0xA4
#define NDIS_OBJECT_TYPE_OFFLOAD 0xA7
#define NDIS_OBJECT_TYPE_OFFLOAD_ENCAPSULATION 0xA8
#define NDIS_OBJECT_TYPE_CONFIGURATION_OBJECT 0xA9

#define NDIS_CONFIGURATION_OBJECT_REVISION_1 1
#define NDIS_SIZEOF_CONFIGURATION_OBJECT_REVISION_1 \
  sizeof(_NDIS_CONFIGURATION_OBJECT)
#define NDIS_STATISTICS_INFO_REVISION_1 1
#define NDIS_SIZEOF_STATISTICS_INFO_REVISION_1 sizeof(_NDIS_STATISTICS_INFO)
#define NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1 1
#define NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1 \
  sizeof(_NET_BUFFER_LIST_POOL_PARAMETERS)
#define NDIS_SG_DMA_DESCRIPTION_REVISION_1 1
#define NDIS_SIZEOF_SG_DMA_DESCRIPTION_REVISION_1 \
  sizeof(_NDIS_SG_DMA_DESCRIPTION)
#define NDIS_MINIPORT_INTERRUPT_REVISION_1 1
#define NDIS_SIZEOF_MINIPORT_INTERRUPT_CHARACTERISTICS_REVISION_1 \
  sizeof(_NDIS_MINIPORT_INTERRUPT_CHARACTERISTICS)
#define NDIS_SIZEOF_RECEIVE_SCALE_CAPABILITIES_REVISION_1 \
  sizeof(_NDIS_RECEIVE_SCALE_CAPABILITIES)
#define NDIS_RECEIVE_SCALE_CAPABILITIES_REVISION_1 1
#define NDIS_STATUS_INDICATION_REVISION_1 1
#define NDIS_SIZEOF_STATUS_INDICATION_REVISION_1 sizeof(_NDIS_STATUS_INDICATION)
#define NDIS_OFFLOAD_REVISION_1 1
#define NDIS_SIZEOF_NDIS_OFFLOAD_REVISION_1 sizeof(_NDIS_OFFLOAD)
#define NDIS_LINK_STATE_REVISION_1 1
#define NDIS_SIZEOF_LINK_STATE_REVISION_1 sizeof(_NDIS_LINK_STATE)
#define NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_1 1
#define NDIS_SIZEOF_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_1 \
  sizeof(_NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES)
#define NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES_REVISION_2 1
#define NDIS_SIZEOF_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES_REVISION_2 \
  sizeof(_NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES)
#define NDIS_MINIPORT_ADAPTER_OFFLOAD_ATTRIBUTES_REVISION_1 1
#define NDIS_SIZEOF_MINIPORT_ADAPTER_OFFLOAD_ATTRIBUTES_REVISION_1 \
  sizeof(_NDIS_MINIPORT_ADAPTER_OFFLOAD_ATTRIBUTES)
#define NDIS_MINIPORT_ADD_DEVICE_REGISTRATION_ATTRIBUTES_REVISION_1 1
#define NDIS_SIZEOF_MINIPORT_ADD_DEVICE_REGISTRATION_ATTRIBUTES_REVISION_1 \
  sizeof(_NDIS_MINIPORT_ADD_DEVICE_REGISTRATION_ATTRIBUTES)
#define NDIS_PM_CAPABILITIES_REVISION_1 1
#define NDIS_SIZEOF_NDIS_PM_CAPABILITIES_REVISION_1 \
  sizeof(_NDIS_PM_CAPABILITIES)
#define NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_2 2
#define NDIS_SIZEOF_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_2 \
  sizeof(_NDIS_MINIPORT_DRIVER_CHARACTERISTICS)
#define NDIS_MINIPORT_PNP_CHARACTERISTICS_REVISION_1 1
#define NDIS_SIZEOF_MINIPORT_PNP_CHARACTERISTICS_REVISION_1 \
  sizeof(_NDIS_MINIPORT_PNP_CHARACTERISTICS)
#define NDIS_INTERRUPT_MODERATION_PARAMETERS_REVISION_1 1
#define NDIS_SIZEOF_INTERRUPT_MODERATION_PARAMETERS_REVISION_1 \
  sizeof(_NDIS_INTERRUPT_MODERATION_PARAMETERS)
#define NDIS_LINK_PARAMETERS_REVISION_1 1
#define NDIS_SIZEOF_LINK_PARAMETERS_REVISION_1 sizeof(_NDIS_LINK_PARAMETERS)
#define NDIS_OFFLOAD_ENCAPSULATION_REVISION_1 1
#define NDIS_SIZEOF_OFFLOAD_ENCAPSULATION_REVISION_1 \
  sizeof(_NDIS_OFFLOAD_ENCAPSULATION)
#define NDIS_RECEIVE_SCALE_CAPABILITIES_REVISION_2 2
#define NDIS_SIZEOF_RECEIVE_SCALE_CAPABILITIES_REVISION_2 \
  sizeof(_NDIS_RECEIVE_SCALE_CAPABILITIES)
#define NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_2 2
#define NDIS_SIZEOF_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_2 \
  sizeof(_NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES)
#define NDIS_OFFLOAD_REVISION_3 3
#define NDIS_SIZEOF_NDIS_OFFLOAD_REVISION_3 sizeof(_NDIS_OFFLOAD)
#define NDIS_PM_CAPABILITIES_REVISION_2 2
#define NDIS_SIZEOF_NDIS_PM_CAPABILITIES_REVISION_2 \
  sizeof(_NDIS_PM_CAPABILITIES)
#define NDIS_TIMER_CHARACTERISTICS_REVISION_1 1
#define NDIS_SIZEOF_TIMER_CHARACTERISTICS_REVISION_1 \
  sizeof(_NDIS_TIMER_CHARACTERISTICS)
#define NDIS_RSS_PROCESSOR_INFO_REVISION_1 1
#define NDIS_SIZEOF_RSS_PROCESSOR_INFO_REVISION_1 \
  sizeof(_NDIS_RSS_PROCESSOR_INFO)
#define NDIS_SIZEOF_RSS_PROCESSOR_REVISION_1 sizeof(_NDIS_RSS_PROCESSOR)
#define NDIS_MSIX_CONFIG_PARAMETERS_REVISION_1 1
#define NDIS_SIZEOF_MSIX_CONFIG_PARAMETERS_REVISION_1 \
  sizeof(NDIS_MSIX_CONFIG_PARAMETERS)

#define NDIS_RSS_CAPS_MESSAGE_SIGNALED_INTERRUPTS 0x01000000
#define NDIS_RSS_CAPS_CLASSIFICATION_AT_ISR 0x02000000
#define NDIS_RSS_CAPS_CLASSIFICATION_AT_DPC 0x04000000
#define NDIS_RSS_CAPS_HASH_TYPE_TCP_IPV4 0x00000100
#define NDIS_RSS_CAPS_HASH_TYPE_TCP_IPV6 0x00000200
#define NDIS_RSS_CAPS_HASH_TYPE_TCP_IPV6_EX 0x00000400
#define NDIS_RSS_CAPS_HASH_TYPE_UDP_IPV4 0x00000800
#define NDIS_RSS_CAPS_HASH_TYPE_UDP_IPV6 0x00001000
#define NDIS_RSS_CAPS_HASH_TYPE_UDP_IPV6_EX 0x00002000
#define NDIS_RSS_PARAM_FLAG_BASE_CPU_UNCHANGED 0x0001
#define NDIS_RSS_PARAM_FLAG_HASH_INFO_UNCHANGED 0x0002
#define NDIS_RSS_PARAM_FLAG_ITABLE_UNCHANGED 0x0004
#define NDIS_RSS_PARAM_FLAG_HASH_KEY_UNCHANGED 0x0008
#define NDIS_RSS_PARAM_FLAG_DISABLE_RSS 0x0010

#define NdisHashFunctionToeplitz 0x00000001
#define NDIS_HASH_FUNCTION_MASK 0x000000FF
#define NDIS_HASH_TYPE_MASK 0x00FFFF00

#define NDIS_RSS_HASH_FUNC_FROM_HASH_INFO(_HashInfo) \
  ((_HashInfo) & (NDIS_HASH_FUNCTION_MASK))
#define NDIS_RSS_HASH_TYPE_FROM_HASH_INFO(_HashInfo) \
  ((_HashInfo) & (NDIS_HASH_TYPE_MASK))
#define NDIS_RSS_INDIRECTION_TABLE_MAX_SIZE_REVISION_2 \
  (128 * sizeof(PROCESSOR_NUMBER))

#define NDIS_HASH_IPV4 0x00000100
#define NDIS_HASH_TCP_IPV4 0x00000200
#define NDIS_HASH_IPV6 0x00000400
#define NDIS_HASH_IPV6_EX 0x00000800
#define NDIS_HASH_TCP_IPV6 0x00001000
#define NDIS_HASH_TCP_IPV6_EX 0x00002000
#define NDIS_HASH_UDP_IPV4 0x00004000
#define NDIS_HASH_UDP_IPV6 0x00008000
#define NDIS_HASH_UDP_IPV6_EX 0x00010000

#define NDIS_STATISTICS_XMIT_OK_SUPPORTED 0x00000001
#define NDIS_STATISTICS_RCV_OK_SUPPORTED 0x00000002
#define NDIS_STATISTICS_XMIT_ERROR_SUPPORTED 0x00000004
#define NDIS_STATISTICS_RCV_ERROR_SUPPORTED 0x00000008
#define NDIS_STATISTICS_RCV_NO_BUFFER_SUPPORTED 0x00000010
#define NDIS_STATISTICS_DIRECTED_BYTES_XMIT_SUPPORTED 0x00000020
#define NDIS_STATISTICS_DIRECTED_FRAMES_XMIT_SUPPORTED 0x00000040
#define NDIS_STATISTICS_MULTICAST_BYTES_XMIT_SUPPORTED 0x00000080
#define NDIS_STATISTICS_MULTICAST_FRAMES_XMIT_SUPPORTED 0x00000100
#define NDIS_STATISTICS_BROADCAST_BYTES_XMIT_SUPPORTED 0x00000200
#define NDIS_STATISTICS_BROADCAST_FRAMES_XMIT_SUPPORTED 0x00000400
#define NDIS_STATISTICS_DIRECTED_BYTES_RCV_SUPPORTED 0x00000800
#define NDIS_STATISTICS_DIRECTED_FRAMES_RCV_SUPPORTED 0x00001000
#define NDIS_STATISTICS_MULTICAST_BYTES_RCV_SUPPORTED 0x00002000
#define NDIS_STATISTICS_MULTICAST_FRAMES_RCV_SUPPORTED 0x00004000
#define NDIS_STATISTICS_BROADCAST_BYTES_RCV_SUPPORTED 0x00008000
#define NDIS_STATISTICS_BROADCAST_FRAMES_RCV_SUPPORTED 0x00010000
#define NDIS_STATISTICS_RCV_CRC_ERROR_SUPPORTED 0x00020000
#define NDIS_STATISTICS_TRANSMIT_QUEUE_LENGTH_SUPPORTED 0x00040000
#define NDIS_STATISTICS_BYTES_RCV_SUPPORTED 0x00080000
#define NDIS_STATISTICS_BYTES_XMIT_SUPPORTED 0x00100000
#define NDIS_STATISTICS_RCV_DISCARDS_SUPPORTED 0x00200000
#define NDIS_STATISTICS_GEN_STATISTICS_SUPPORTED 0x00400000
#define NDIS_STATISTICS_XMIT_DISCARDS_SUPPORTED 0x08000000

#define NDIS_PROTOCOL_ID_DEFAULT 0x00
#define NDIS_PROTOCOL_ID_TCP_IP 0x02
#define NDIS_PROTOCOL_ID_IPX 0x06
#define NDIS_PROTOCOL_ID_NBF 0x07
#define NDIS_PROTOCOL_ID_MAX 0x0F
#define NDIS_PROTOCOL_ID_MASK 0x0F

#define NDIS_RECEIVE_FLAGS_DISPATCH_LEVEL 0x00000001
#define NDIS_RECEIVE_FLAGS_RESOURCES 0x00000002

#define OID_GEN_HARDWARE_STATUS 0x00010102
#define OID_GEN_MAXIMUM_SEND_PACKETS 0x00010115
#define OID_GEN_XMIT_ERROR 0x00020103
#define OID_GEN_RCV_ERROR 0x00020104
#define OID_GEN_RCV_NO_BUFFER 0x00020105
#define OID_GEN_STATISTICS 0x00020106
#define OID_GEN_XMIT_OK 0x00020101
#define OID_GEN_RCV_OK 0x00020102
#define OID_GEN_TRANSMIT_QUEUE_LENGTH 0x0002020E
#define OID_GEN_INIT_TIME_MS 0x00020213
#define OID_GEN_RESET_COUNTS 0x00020214
#define OID_GEN_MEDIA_SENSE_COUNTS 0x00020215
#define OID_GEN_TRANSMIT_BUFFER_SPACE 0x00010108
#define OID_GEN_RECEIVE_BUFFER_SPACE 0x00010109
#define OID_GEN_TRANSMIT_BLOCK_SIZE 0x0001010A
#define OID_GEN_RECEIVE_BLOCK_SIZE 0x0001010B
#define OID_GEN_VENDOR_ID 0x0001010C
#define OID_GEN_VENDOR_DESCRIPTION 0x0001010D
#define OID_GEN_VENDOR_DRIVER_VERSION 0x00010116
#define OID_GEN_SUPPORTED_GUIDS 0x00010117
#define OID_GEN_CURRENT_PACKET_FILTER 0x0001010E
#define OID_GEN_CURRENT_LOOKAHEAD 0x0001010F
#define OID_GEN_MAXIMUM_TOTAL_SIZE 0x00010111
#define OID_GEN_LINK_PARAMETERS 0x00010208
#define OID_GEN_INTERRUPT_MODERATION 0x00010209
#define OID_IP4_OFFLOAD_STATS 0xFC010209
#define OID_TCP_OFFLOAD_PARAMETERS 0xFC01020C
#define OID_OFFLOAD_ENCAPSULATION 0x0101010A
#define OID_802_3_PERMANENT_ADDRESS 0x01010101
#define OID_802_3_CURRENT_ADDRESS 0x01010102
#define OID_PNP_SET_POWER 0xFD010101
#define OID_PNP_QUERY_POWER 0xFD010102
#define OID_GEN_RECEIVE_SCALE_PARAMETERS 0x00010204
#define OID_802_3_MULTICAST_LIST 0x01010103
#define OID_802_3_MAXIMUM_LIST_SIZE 0x01010104
#define OID_GEN_RECEIVE_HASH 0x0001021F
#define OID_GEN_MEDIA_SUPPORTED 0x00010103
#define OID_GEN_MEDIA_IN_USE 0x00010104
#define OID_802_3_RCV_ERROR_ALIGNMENT 0x01020101
#define OID_802_3_XMIT_ONE_COLLISION 0x01020102
#define OID_802_3_XMIT_MORE_COLLISIONS 0x01020103

#define NDIS_MINIPORT_ATTRIBUTES_HARDWARE_DEVICE 0x00000001
#define NDIS_MINIPORT_ATTRIBUTES_NDIS_WDM 0x00000002
#define NDIS_MINIPORT_ATTRIBUTES_SURPRISE_REMOVE_OK 0x00000004
#define NDIS_MINIPORT_ATTRIBUTES_NOT_CO_NDIS 0x00000008
#define NDIS_MINIPORT_ATTRIBUTES_DO_NOT_BIND_TO_ALL_CO 0x00000010
#define NDIS_MINIPORT_ATTRIBUTES_NO_HALT_ON_SUSPEND 0x00000020
#define NDIS_MINIPORT_ATTRIBUTES_BUS_MASTER 0x00000040
#define NDIS_MINIPORT_ATTRIBUTES_CONTROLS_DEFAULT_PORT 0x00000080
#define NDIS_MINIPORT_ATTRIBUTES_NO_PAUSE_ON_SUSPEND 0x00000100
#define NDIS_MINIPORT_ATTRIBUTES_NO_OID_INTERCEPT_ON_NONDEFAULT_PORTS 0x00000200
#define NDIS_MINIPORT_ATTRIBUTES_REGISTER_BUGCHECK_CALLBACK 0x00000400

#define NDIS_MAC_OPTION_COPY_LOOKAHEAD_DATA 0x00000001
#define NDIS_MAC_OPTION_RECEIVE_SERIALIZED 0x00000002
#define NDIS_MAC_OPTION_TRANSFERS_NOT_PEND 0x00000004
#define NDIS_MAC_OPTION_NO_LOOPBACK 0x00000008
#define NDIS_MAC_OPTION_EOTX_INDICATION 0x00000020
#define NDIS_MAC_OPTION_8021P_PRIORITY 0x00000040
#define NDIS_MAC_OPTION_SUPPORTS_MAC_ADDRESS_OVERWRITE 0x00000080
#define NDIS_MAC_OPTION_RECEIVE_AT_DPC 0x00000100
#define NDIS_MAC_OPTION_8021Q_VLAN 0x00000200
#define NDIS_MAC_OPTION_RESERVED 0x80000000

#define NDIS_PACKET_TYPE_DIRECTED 0x00000001
#define NDIS_PACKET_TYPE_MULTICAST 0x00000002
#define NDIS_PACKET_TYPE_ALL_MULTICAST 0x00000004
#define NDIS_PACKET_TYPE_BROADCAST 0x00000008
#define NDIS_PACKET_TYPE_SOURCE_ROUTING 0x00000010
#define NDIS_PACKET_TYPE_PROMISCUOUS 0x00000020
#define NDIS_PACKET_TYPE_SMT 0x00000040
#define NDIS_PACKET_TYPE_ALL_LOCAL 0x00000080
#define NDIS_PACKET_TYPE_GROUP 0x00001000
#define NDIS_PACKET_TYPE_ALL_FUNCTIONAL 0x00002000
#define NDIS_PACKET_TYPE_FUNCTIONAL 0x00004000
#define NDIS_PACKET_TYPE_MAC_FRAME 0x00008000
#define NDIS_PACKET_TYPE_NO_LOCAL 0x00010000

#define NDIS_SEND_FLAGS_DISPATCH_LEVEL 0x00000001

#define NDIS_RETURN_FLAGS_DISPATCH_LEVEL 0x00000001
#define NDIS_RETURN_FLAGS_SINGLE_QUEUE 0x00000002

#define IF_TYPE_ETHERNET_CSMACD 6

#define EVENT_NDIS_RESOURCE_CONFLICT 0xC0001388
#define EVENT_NDIS_OUT_OF_RESOURCE 0xC0001389
#define EVENT_NDIS_HARDWARE_FAILURE 0xC000138A
#define EVENT_NDIS_ADAPTER_NOT_FOUND 0xC000138B
#define EVENT_NDIS_INTERRUPT_CONNECT 0xC000138C
#define EVENT_NDIS_DRIVER_FAILURE 0xC000138D
#define EVENT_NDIS_BAD_VERSION 0xC000138E
#define EVENT_NDIS_TIMEOUT 0x8000138F
#define EVENT_NDIS_NETWORK_ADDRESS 0xC0001390
#define EVENT_NDIS_UNSUPPORTED_CONFIGURATION 0xC0001391
#define EVENT_NDIS_INVALID_VALUE_FROM_ADAPTER 0xC0001392
#define EVENT_NDIS_MISSING_CONFIGURATION_PARAMETER 0xC0001393
#define EVENT_NDIS_BAD_IO_BASE_ADDRESS 0xC0001394
#define EVENT_NDIS_RECEIVE_SPACE_SMALL 0x40001395
#define EVENT_NDIS_ADAPTER_DISABLED 0x80001396
#define EVENT_NDIS_IO_PORT_CONFLICT 0x80001397
#define EVENT_NDIS_PORT_OR_DMA_CONFLICT 0x80001398
#define EVENT_NDIS_MEMORY_CONFLICT 0x80001399
#define EVENT_NDIS_INTERRUPT_CONFLICT 0x8000139A
#define EVENT_NDIS_DMA_CONFLICT 0x8000139B
#define EVENT_NDIS_INVALID_DOWNLOAD_FILE_ERROR 0xC000139C
#define EVENT_NDIS_MAXRECEIVES_ERROR 0x8000139D
#define EVENT_NDIS_MAXTRANSMITS_ERROR 0x8000139E
#define EVENT_NDIS_MAXFRAMESIZE_ERROR 0x8000139F
#define EVENT_NDIS_MAXINTERNALBUFS_ERROR 0x800013A0
#define EVENT_NDIS_MAXMULTICAST_ERROR 0x800013A1
#define EVENT_NDIS_PRODUCTID_ERROR 0x800013A2
#define EVENT_NDIS_LOBE_FAILUE_ERROR 0x800013A3
#define EVENT_NDIS_SIGNAL_LOSS_ERROR 0x800013A4
#define EVENT_NDIS_REMOVE_RECEIVED_ERROR 0x800013A5
#define EVENT_NDIS_TOKEN_RING_CORRECTION 0x400013A6
#define EVENT_NDIS_ADAPTER_CHECK_ERROR 0xC00013A7
#define EVENT_NDIS_RESET_FAILURE_ERROR 0x800013A8
#define EVENT_NDIS_CABLE_DISCONNECTED_ERROR 0x800013A9
#define EVENT_NDIS_RESET_FAILURE_CORRECTION 0x800013AA

#define NDIS_ERROR_CODE ULONG

#define NDIS_ERROR_CODE_RESOURCE_CONFLICT EVENT_NDIS_RESOURCE_CONFLICT
#define NDIS_ERROR_CODE_OUT_OF_RESOURCES EVENT_NDIS_OUT_OF_RESOURCE
#define NDIS_ERROR_CODE_HARDWARE_FAILURE EVENT_NDIS_HARDWARE_FAILURE
#define NDIS_ERROR_CODE_ADAPTER_NOT_FOUND EVENT_NDIS_ADAPTER_NOT_FOUND
#define NDIS_ERROR_CODE_INTERRUPT_CONNECT EVENT_NDIS_INTERRUPT_CONNECT
#define NDIS_ERROR_CODE_DRIVER_FAILURE EVENT_NDIS_DRIVER_FAILURE
#define NDIS_ERROR_CODE_BAD_VERSION EVENT_NDIS_BAD_VERSION
#define NDIS_ERROR_CODE_TIMEOUT EVENT_NDIS_TIMEOUT
#define NDIS_ERROR_CODE_NETWORK_ADDRESS EVENT_NDIS_NETWORK_ADDRESS
#define NDIS_ERROR_CODE_UNSUPPORTED_CONFIGURATION \
  EVENT_NDIS_UNSUPPORTED_CONFIGURATION
#define NDIS_ERROR_CODE_INVALID_VALUE_FROM_ADAPTER \
  EVENT_NDIS_INVALID_VALUE_FROM_ADAPTER
#define NDIS_ERROR_CODE_MISSING_CONFIGURATION_PARAMETER \
  EVENT_NDIS_MISSING_CONFIGURATION_PARAMETER
#define NDIS_ERROR_CODE_BAD_IO_BASE_ADDRESS EVENT_NDIS_BAD_IO_BASE_ADDRESS
#define NDIS_ERROR_CODE_RECEIVE_SPACE_SMALL EVENT_NDIS_RECEIVE_SPACE_SMALL
#define NDIS_ERROR_CODE_ADAPTER_DISABLED EVENT_NDIS_ADAPTER_DISABLED

#endif  // THIRD_PARTY_CLOUD_WINDOWS_GVNIC_TESTING_NDIS_TYPES_H__
