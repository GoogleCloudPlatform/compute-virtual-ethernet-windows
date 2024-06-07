#include "third_party/cloud_windows_gvnic/release/testing/ndis.h"

#include <string.h>

#include "testing/base/public/gunit.h"
#include "third_party/absl/synchronization/mutex.h"
#include "third_party/cloud_windows_gvnic/release/testing/windows-types.h"

namespace ndis_testing {

NdisStub* ndis_mock_object = nullptr;

void NdisStub::PAGED_CODE_impl(absl::string_view) {
  // Do nothing.
}

void NdisStub::NT_ASSERT_impl(absl::string_view expression, bool val) {
  // Do nothing.
}

void NdisStub::WPP_INIT_TRACING_impl(PDRIVER_OBJECT DriverObject,
                                     PUNICODE_STRING RegistryPath) {
  // Do nothing.
}
void NdisStub::WPP_CLEANUP_impl(PDRIVER_OBJECT DriverObject) {
  // Do nothing.
}

void NdisStub::NdisZeroMemory_impl(PVOID Destination, SIZE_T Length) {
  memset(Destination, 0, Length);
}

void NdisStub::NdisMoveMemory_impl(PVOID Destination, const PVOID Source,
                                   SIZE_T Length) {
  memcpy(Destination, Source, Length);
}

NTSTATUS NdisStub::NdisMSetMiniportAttributes_impl(
    NDIS_HANDLE NdisMiniportHandle,
    PNDIS_MINIPORT_ADAPTER_ATTRIBUTES MiniportAttributes) {
  return STATUS_SUCCESS;
}

// TODO: Consolidate NET_BUFFER mocking if we're going to keep doing it
NDIS_STATUS NdisStub::NdisRetreatNetBufferDataStart_impl(
    NET_BUFFER* NetBuffer, ULONG DataOffsetDelta, ULONG DataBackFill,
    NET_BUFFER_ALLOCATE_MDL* AllocateMdlHandler) {
  NET_BUFFER_DATA_OFFSET(NetBuffer) -= DataOffsetDelta;
  NET_BUFFER_DATA_LENGTH(NetBuffer) += DataOffsetDelta;
  if (NET_BUFFER_DATA_OFFSET(NetBuffer) < 0) {
    return NDIS_STATUS_FAILURE;
  }
  PMDL current_mdl = NET_BUFFER_FIRST_MDL(NetBuffer);
  ULONG data_offset_total = NET_BUFFER_DATA_OFFSET(NetBuffer);
  while (current_mdl != nullptr && 0 < data_offset_total) {
    UINT32 pass_len = min(current_mdl->ByteCount, data_offset_total);
    data_offset_total -= pass_len;
    if (0 == data_offset_total) {
      NET_BUFFER_CURRENT_MDL(NetBuffer) = current_mdl;
      NET_BUFFER_CURRENT_MDL_OFFSET(NetBuffer) = pass_len;
      return NDIS_STATUS_SUCCESS;
    }
    current_mdl = current_mdl->Next;
  }
  return NDIS_STATUS_FAILURE;
}

void NdisStub::NdisAdvanceNetBufferDataStart_impl(
    NET_BUFFER* NetBuffer, ULONG DataOffsetDelta, BOOLEAN FreeMdl,
    NET_BUFFER_FREE_MDL* FreeMdlHandler) {
  NET_BUFFER_DATA_OFFSET(NetBuffer) += DataOffsetDelta;
  NET_BUFFER_DATA_LENGTH(NetBuffer) -= DataOffsetDelta;
  PMDL current_mdl = NET_BUFFER_CURRENT_MDL(NetBuffer);
  while (current_mdl != nullptr && 0 < DataOffsetDelta) {
    UINT32 pass_len = min(current_mdl->ByteCount - NetBuffer->CurrentMdlOffset,
                          DataOffsetDelta);
    DataOffsetDelta -= pass_len;

    if (0 == DataOffsetDelta) {
      NET_BUFFER_CURRENT_MDL(NetBuffer) = current_mdl;
      NET_BUFFER_CURRENT_MDL_OFFSET(NetBuffer) =
          pass_len + current_mdl->ByteOffset;
      return;
    }
    current_mdl = current_mdl->Next;
    if (current_mdl != nullptr) {
      NET_BUFFER_CURRENT_MDL_OFFSET(NetBuffer) = current_mdl->ByteOffset;
    }
  }
}

PNET_BUFFER_LIST NdisStub::NdisAllocateNetBufferAndNetBufferList_impl(
    NDIS_HANDLE PoolHandle, USHORT ContextSize, USHORT ContextBackFill,
    PMDL MdlChain, ULONG DataOffset, SIZE_T DataLength) {
  PNET_BUFFER_LIST nbl =
      reinterpret_cast<PNET_BUFFER_LIST>(calloc(1, sizeof(NET_BUFFER_LIST)));
  PNET_BUFFER nb = reinterpret_cast<PNET_BUFFER>(calloc(1, sizeof(NET_BUFFER)));
  nbl->FirstNetBuffer = nb;
  nbl->NdisPoolHandle = PoolHandle;

  return nbl;
}
void NdisStub::NdisFreeNetBufferList_impl(PNET_BUFFER_LIST NetBufferList) {
  PNET_BUFFER curr = NetBufferList->FirstNetBuffer;
  while (curr != nullptr) {
    PNET_BUFFER next = curr->Next;
    free(curr);
    curr = next;
  }

  free(NetBufferList);
}

PMDL NdisStub::NdisAllocateMdl_impl(NDIS_HANDLE NdisHandle,
                                    PVOID VirtualAddress, UINT Length) {
  PMDL mdl = reinterpret_cast<PMDL>(calloc(1, sizeof(MDL)));
  mdl->MappedSystemVa = VirtualAddress;
  mdl->ByteCount = Length;

  return mdl;
}

// TODO: Verify this is the proper member in WinDbg
void NdisStub::NdisAdjustMdlLength_impl(PMDL Mdl, UINT Length) {
  Mdl->ByteCount = Length;
}

void NdisStub::NdisFreeMdl_impl(PMDL mdl) { free(mdl); }

PVOID NdisStub::NdisAllocateMemoryWithTagPriority_impl(
    NDIS_HANDLE NdisHandle, UINT Length, ULONG Tag, EX_POOL_PRIORITY Priority) {
  return malloc(Length);
}

PVOID NdisStub::NdisGetDataBuffer_impl(NET_BUFFER* NetBuffer, ULONG BytesNeeded,
                                       PVOID Storage, ULONG AlignMultiple,
                                       ULONG AlignOffset) {
  return (PVOID)((char*)NET_BUFFER_CURRENT_MDL(NetBuffer)->MappedSystemVa +
                 NET_BUFFER_CURRENT_MDL_OFFSET(NetBuffer));
}

void NdisStub::NdisFreeMemoryWithTagPriority_impl(NDIS_HANDLE NdisHandle,
                                                  PVOID VirtualAddress,
                                                  ULONG Tag) {
  free(VirtualAddress);
}
void NdisStub::NdisFreeMemory_impl(PVOID VirtualAddress, UINT Length,
                                   UINT MemoryFlags) {
  free(VirtualAddress);
}

void NdisStub::NdisMAllocateSharedMemory_impl(
    NDIS_HANDLE MiniportAdapterHandle, ULONG Length, BOOLEAN Cached,
    PVOID* VirtualAddress, PNDIS_PHYSICAL_ADDRESS PhysicalAddress) {
  posix_memalign(VirtualAddress, PAGE_SIZE, Length);
  PhysicalAddress->QuadPart =
      reinterpret_cast<LONGLONG>(*VirtualAddress) + kPhysicalAddressOffset;
}

void NdisStub::NdisMFreeSharedMemory_impl(
    NDIS_HANDLE MiniportAdapterHandle, ULONG Length, BOOLEAN Cached,
    PVOID VirtualAddress, NDIS_PHYSICAL_ADDRESS PhysicalAddress) {
  free(VirtualAddress);
}

CCHAR NdisStub::NdisSystemProcessorCount_impl() { return 1; }
ULONG NdisStub::NdisGroupMaxProcessorCount_impl(USHORT Group) { return 1; }

ULONG NdisStub::KeGetCurrentProcessorNumberEx_impl(
    PPROCESSOR_NUMBER ProcNumber) {
  return 0;
}

ULONG NdisStub::KeGetProcessorIndexFromNumber_impl(
    PPROCESSOR_NUMBER ProcNumber) {
  return ProcNumber->Number;
}

NTSTATUS NdisStub::KeGetProcessorNumberFromIndex_impl(
    ULONG ProcIndex, PPROCESSOR_NUMBER ProcNumber) {
  ProcNumber->Group = 0;
  ProcNumber->Number = ProcIndex;
  return STATUS_SUCCESS;
}

ULONG NdisStub::KeQueryActiveProcessorCountEx_impl(USHORT GroupNumber) {
  return 1L;
}

void NdisStub::KeQueryTickCount_impl(_Out_ PLARGE_INTEGER CurrentCount) {}

NDIS_STATUS NdisStub::NdisOpenConfigurationEx_impl(
    PNDIS_CONFIGURATION_OBJECT ConfigObject, PNDIS_HANDLE ConfigurationHandle) {
  *ConfigurationHandle = malloc(sizeof(NDIS_CONFIGURATION_PARAMETER));
  return NDIS_STATUS_SUCCESS;
}

void NdisStub::NdisReadConfiguration_impl(
    PNDIS_STATUS Status, PNDIS_CONFIGURATION_PARAMETER* ParameterValue,
    NDIS_HANDLE ConfigurationHandle, PNDIS_STRING Keyword,
    NDIS_PARAMETER_TYPE ParameterType) {
  *ParameterValue =
      reinterpret_cast<NDIS_CONFIGURATION_PARAMETER*>(ConfigurationHandle);
  memset(*ParameterValue, 0, sizeof(NDIS_CONFIGURATION_PARAMETER));

  // Mock this function if you actually need to handle non ASCII characters.
  std::wstring keyword_wstr(Keyword->Buffer);
  std::string keyword_str(keyword_wstr.cbegin(), keyword_wstr.cend());

  *Status = NDIS_STATUS_SUCCESS;

  // Useful defaults.
  if (keyword_str == "NumberOfTxQueue") {
    (*ParameterValue)->ParameterData.IntegerData = 1;
  } else if (keyword_str == "NumberOfRxQueue") {
    (*ParameterValue)->ParameterData.IntegerData = 2;
  } else if (keyword_str == "*RSS") {
    (*ParameterValue)->ParameterData.IntegerData = 1;
  } else if (keyword_str == "DioriteQueue") {
    (*ParameterValue)->ParameterData.IntegerData = 1;
  } else {
    *Status = NDIS_STATUS_FAILURE;
  }
}

void NdisStub::NdisReadNetworkAddress_impl(PNDIS_STATUS Status,
                                           PVOID* NetworkAddress,
                                           PUINT NetworkAddressLength,
                                           NDIS_HANDLE ConfigurationHandle) {
  *Status = NDIS_STATUS_FAILURE;
}

void NdisStub::NdisCloseConfiguration_impl(NDIS_HANDLE ConfigurationHandle) {
  free(ConfigurationHandle);
}

PVOID NdisStub::MmGetSystemAddressForMdlSafe_impl(PMDL mdl,
                                                  MM_PAGE_PRIORITY priority) {
  return mdl->MappedSystemVa;
}

NDIS_STATUS NdisStub::NdisMMapIoSpace_impl(
    PVOID* VirtualAddress, NDIS_HANDLE MiniportAdapterHandle,
    NDIS_PHYSICAL_ADDRESS PhysicalAddress, UINT Length) {
  *VirtualAddress = reinterpret_cast<PVOID>(PhysicalAddress.QuadPart -
                                            kPhysicalAddressOffset);
  return NDIS_STATUS_SUCCESS;
}
void NdisStub::NdisMUnmapIoSpace_impl(NDIS_HANDLE MiniportAdapterHandle,
                                      PVOID VirtualAddress, UINT Length) {
  // Do nothing.
}

NDIS_STATUS NdisStub::NdisMAllocateNetBufferSGList_impl(
    NDIS_HANDLE NdisMiniportDmaHandle, PNET_BUFFER NetBuffer, PVOID Context,
    ULONG Flags, PVOID ScatterGatherListBuffer,
    ULONG ScatterGatherListBufferSize) {
  if (ScatterGatherListBuffer != nullptr) {
    // Touch every byte of the provided buffer to ensure that it's valid memory.
    UCHAR* buffer = reinterpret_cast<UCHAR*>(ScatterGatherListBuffer);
    for (uint32 i = 0; i < ScatterGatherListBufferSize; i++) {
      buffer[i] = i % 2;
    }
  }

  return NDIS_STATUS_SUCCESS;
}
void NdisStub::NdisMFreeNetBufferSGList_impl(NDIS_HANDLE NdisMiniportDmaHandle,
                                             PSCATTER_GATHER_LIST pSGL,
                                             PNET_BUFFER NetBuffer) {
  // Do nothing.
}

NDIS_HANDLE NdisStub::NdisAllocateNetBufferListPool_impl(
    NDIS_HANDLE NdisHandle, PNET_BUFFER_LIST_POOL_PARAMETERS Parameters) {
  return NdisHandle;
}
void NdisStub::NdisFreeNetBufferListPool_impl(NDIS_HANDLE PoolHandle) {
  // Do nothing.
}

NDIS_STATUS NdisStub::NdisMRegisterScatterGatherDma_impl(
    NDIS_HANDLE MiniportAdapterHandle, PNDIS_SG_DMA_DESCRIPTION DmaDescription,
    PNDIS_HANDLE NdisMiniportDmaHandle) {
  *NdisMiniportDmaHandle = MiniportAdapterHandle;
  return NDIS_STATUS_SUCCESS;
}
void NdisStub::NdisMDeregisterScatterGatherDma_impl(
    NDIS_HANDLE NdisMiniportDmaHandle) {
  // Do nothing.
}

NDIS_STATUS NdisStub::NdisMRegisterInterruptEx_impl(
    NDIS_HANDLE MiniportAdapterHandle, NDIS_HANDLE MiniportInterruptContext,
    PNDIS_MINIPORT_INTERRUPT_CHARACTERISTICS MiniportInterruptCharacteristics,
    PNDIS_HANDLE NdisInterruptHandle) {
  UINT32 bytes = sizeof(IO_INTERRUPT_MESSAGE_INFO) +
                 sizeof(IO_INTERRUPT_MESSAGE_INFO_ENTRY) * 2;
  *NdisInterruptHandle = malloc(bytes);
  memset(*NdisInterruptHandle, 0, bytes);

  MiniportInterruptCharacteristics->InterruptType = NDIS_CONNECT_MESSAGE_BASED;
  MiniportInterruptCharacteristics->MessageInfoTable =
      reinterpret_cast<PIO_INTERRUPT_MESSAGE_INFO>(*NdisInterruptHandle);
  MiniportInterruptCharacteristics->MessageInfoTable->MessageCount = 3;

  return NDIS_STATUS_SUCCESS;
}
void NdisStub::NdisMDeregisterInterruptEx_impl(
    NDIS_HANDLE NdisInterruptHandle) {
  free(NdisInterruptHandle);
}

NDIS_STATUS NdisStub::NdisMRegisterMiniportDriver_impl(
    PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath,
    NDIS_HANDLE MiniportDriverContext,
    PNDIS_MINIPORT_DRIVER_CHARACTERISTICS MiniportDriverCharacteristics,
    PNDIS_HANDLE NdisMiniportDriverHandle) {
  return NDIS_STATUS_SUCCESS;
}
void NdisStub::NdisMDeregisterMiniportDriver_impl(
    NDIS_HANDLE NdisMiniportDriverHandle) {
  // Do nothing.
}

NDIS_STATUS NdisStub::NdisSetOptionalHandlers_impl(
    NDIS_HANDLE NdisHandle, PNDIS_DRIVER_OPTIONAL_HANDLERS OptionalHandlers) {
  return NDIS_STATUS_SUCCESS;
}

void NdisStub::NdisAllocateSpinLock_impl(PNDIS_SPIN_LOCK SpinLock) {
  SpinLock->SpinLock = new absl::Mutex();
}
void NdisStub::NdisFreeSpinLock_impl(PNDIS_SPIN_LOCK SpinLock) {
  delete SpinLock->SpinLock;
}
void NdisStub::NdisDprAcquireSpinLock_impl(PNDIS_SPIN_LOCK SpinLock) {
  ASSERT_NE(SpinLock->SpinLock, nullptr);
  ASSERT_TRUE(SpinLock->SpinLock->TryLock());
}
void NdisStub::NdisAcquireSpinLock_impl(PNDIS_SPIN_LOCK SpinLock) {
  ASSERT_NE(SpinLock->SpinLock, nullptr);
  ASSERT_TRUE(SpinLock->SpinLock->TryLock());
}
void NdisStub::NdisDprReleaseSpinLock_impl(PNDIS_SPIN_LOCK SpinLock) {
  ASSERT_NE(SpinLock->SpinLock, nullptr);
  SpinLock->SpinLock->AssertHeld();
  SpinLock->SpinLock->Unlock();
}
void NdisStub::NdisReleaseSpinLock_impl(PNDIS_SPIN_LOCK SpinLock) {
  ASSERT_NE(SpinLock->SpinLock, nullptr);
  SpinLock->SpinLock->AssertHeld();
  SpinLock->SpinLock->Unlock();
}

void NdisStub::NdisInitializeSListHead_impl(PSLIST_HEADER SListHeader) {
  InitializeSListHead(SListHeader);
}
void NdisStub::NdisInterlockedPushEntrySList_impl(PSLIST_HEADER SListHeader,
                                                  PSINGLE_LIST_ENTRY SListEntry,
                                                  PNDIS_SPIN_LOCK SpinLock) {
  absl::MutexLock lock(SpinLock->SpinLock);
  PushEntryList(&(SListHeader)->Next, SListEntry);
}
PSINGLE_LIST_ENTRY
NdisStub::NdisInterlockedPopEntrySList_impl(PSLIST_HEADER SListHeader,
                                            PNDIS_SPIN_LOCK SpinLock) {
  absl::MutexLock lock(SpinLock->SpinLock);
  return PopEntryList(&(SListHeader)->Next);
}

LONG NdisStub::NdisInterlockedIncrement_impl(LONG* Addend) {
  return ++(*Addend);
}
LONG NdisStub::NdisInterlockedDecrement_impl(LONG* Addend) {
  return --(*Addend);
}

void NdisStub::NdisInitializeListHead_impl(PLIST_ENTRY ListHead) {
  InitializeListHead(ListHead);
}
void NdisStub::NdisInterlockedInsertTailList_impl(PLIST_ENTRY ListHead,
                                                  PLIST_ENTRY ListEntry,
                                                  PNDIS_SPIN_LOCK SpinLock) {
  absl::MutexLock lock(SpinLock->SpinLock);
  InsertTailList(ListHead, ListEntry);
}
void NdisStub::NdisInterlockedInsertHeadList_impl(PLIST_ENTRY ListHead,
                                                  PLIST_ENTRY ListEntry,
                                                  PNDIS_SPIN_LOCK SpinLock) {
  absl::MutexLock lock(SpinLock->SpinLock);
  InsertHeadList(ListHead, ListEntry);
}
PLIST_ENTRY NdisStub::NdisInterlockedRemoveHeadList_impl(
    PLIST_ENTRY ListHead, PNDIS_SPIN_LOCK SpinLock) {
  absl::MutexLock lock(SpinLock->SpinLock);
  return ExInterlockedRemoveHeadList(ListHead);
}

void NdisStub::NdisInitializeNPagedLookasideList_impl(
    PNPAGED_LOOKASIDE_LIST Lookaside, PALLOCATE_FUNCTION Allocate,
    PFREE_FUNCTION Free, ULONG Flags, SIZE_T Size, ULONG Tag, USHORT Depth) {
  Lookaside->Size = Size;
}
void NdisStub::NdisDeleteNPagedLookasideList_impl(
    PNPAGED_LOOKASIDE_LIST Lookaside) {
  Lookaside->Size = 0;
}
PVOID NdisStub::NdisAllocateFromNPagedLookasideList_impl(
    PNPAGED_LOOKASIDE_LIST Lookaside) {
  return malloc(Lookaside->Size);
}
void NdisStub::NdisFreeToNPagedLookasideList_impl(
    PNPAGED_LOOKASIDE_LIST Lookaside, PVOID buffer) {
  free(buffer);
}

void NdisStub::NdisMSendNetBufferListsComplete_impl(
    NDIS_HANDLE MiniportAdapterHandle, PNET_BUFFER_LIST NetBufferList,
    ULONG SendCompleteFlags) {
  // Do nothing.
}
void NdisStub::NdisMIndicateReceiveNetBufferLists_impl(
    NDIS_HANDLE MiniportAdapterHandle, PNET_BUFFER_LIST NetBufferList,
    NDIS_PORT_NUMBER PortNumber, ULONG NumberOfNetBufferLists,
    ULONG ReceiveFlags) {
  if ((ReceiveFlags & NDIS_RECEIVE_FLAGS_RESOURCES) == 0) {
    while (NetBufferList != nullptr) {
      PNET_BUFFER nb = NetBufferList->FirstNetBuffer;
      while (nb != nullptr) {
        PMDL mdl = nb->CurrentMdl;
        while (mdl != nullptr) {
          PMDL next = mdl->Next;
          free(mdl);
          mdl = next;
        }
        nb = nb->Next;
      }
      NetBufferList = NetBufferList->Next;
    }
  }
}
void NdisStub::NdisMIndicateStatusEx_impl(
    NDIS_HANDLE MiniportAdapterHandle,
    PNDIS_STATUS_INDICATION StatusIndication) {
  // Do nothing.
}

void NdisStub::NdisMResetMiniport_impl(NDIS_HANDLE MiniportAdapterHandle) {
  // Do nothing.
}

void NdisStub::NdisInitializeString_impl(PNDIS_STRING Destination,
                                         PUCHAR Source) {
  uint32 len = std::strlen((char*)Source) + 1;

  Destination->Length = len * sizeof(WCHAR);
  Destination->MaximumLength = Destination->Length;
  Destination->Buffer = static_cast<PWSTR>(malloc(Destination->Length));

  std::mbstowcs(Destination->Buffer, (const char*)Source, len);
}

void NdisStub::NdisMSleep_impl(ULONG MicrosecondsToSleep) {
  // Do nothing.
}

void NdisStub::NdisWriteErrorLogEntry_impl(NDIS_HANDLE NdisAdapterHandle,
                                           NDIS_ERROR_CODE ErrorCode,
                                           ULONG NumberOfErrorValues,
                                           ULONG Val1, ULONG Val2) {
  // Do nothing.
}

void NdisStub::NdisWriteRegisterUlong_impl(PULONG addr, ULONG val) {
  *addr = val;
}

BOOLEAN NdisStub::NdisMSynchronizeWithInterruptEx_impl(
    NDIS_HANDLE NdisInterruptHandle, ULONG MessageId,
    MINIPORT_SYNCHRONIZE_INTERRUPT_HANDLER SynchronizeFunction,
    PVOID SynchronizeContext) {
  return SynchronizeFunction(SynchronizeContext);
}

NDIS_STATUS NdisStub::NdisGetRssProcessorInformation_impl(
    NDIS_HANDLE NdisHandle, PNDIS_RSS_PROCESSOR_INFO RssProcessorInfo,
    PSIZE_T Size) {
  return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS NdisStub::NdisMConfigMSIXTableEntry_impl(
    NDIS_HANDLE NdisMiniportHandle,
    PNDIS_MSIX_CONFIG_PARAMETERS MSIXConfigParameters) {
  return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS NdisStub::NdisAllocateTimerObject_impl(
    NDIS_HANDLE NdisHandle, PNDIS_TIMER_CHARACTERISTICS TimerCharacteristics,
    PNDIS_HANDLE pTimerObject) {
  *pTimerObject = NdisHandle;
  return NDIS_STATUS_SUCCESS;
}

bool NdisStub::NdisSetCoalescableTimerObject_impl(NDIS_HANDLE TimerObject,
                                                  LARGE_INTEGER DueTime,
                                                  LONG MillisecondsPeriod,
                                                  PVOID FunctionContext,
                                                  ULONG Tolerance) {
  return false;  // False is not a failure status.
}

bool NdisStub::NdisCancelTimerObject_impl(NDIS_HANDLE TimerObject) {
  return false;  // False is not a failure status.
}

NDIS_HANDLE NdisStub::NdisAllocateIoWorkItem_impl(
    NDIS_HANDLE NdisObjectHandle) {
  return NdisObjectHandle;
}
void NdisStub::NdisQueueIoWorkItem_impl(NDIS_HANDLE NdisIoWorkItemHandle,
                                        NDIS_IO_WORKITEM_ROUTINE Routine,
                                        PVOID WorkItemContext) {
  // Routine is always invoked at passive.
  KIRQL old_irql = ndis_testing::ndis_mock_object->irql_;
  ndis_testing::ndis_mock_object->irql_ = PASSIVE_LEVEL;

  Routine(WorkItemContext, NdisIoWorkItemHandle);

  ndis_testing::ndis_mock_object->irql_ = old_irql;
}
void NdisStub::NdisFreeIoWorkItem_impl(NDIS_HANDLE NdisIoWorkItemHandle) {
  // Do nothing.
}

void NdisStub::NdisMResetComplete_impl(NDIS_HANDLE MiniportAdapterHandle,
                                       NDIS_STATUS Status,
                                       BOOLEAN AddressingReset) {
  // Do nothing.
}

KAFFINITY NdisStub::NdisMQueueDpcEx_impl(NDIS_HANDLE NdisInterruptHandle,
                                         ULONG MessageId,
                                         PGROUP_AFFINITY TargetProcessors,
                                         PVOID MiniportDpcContext) {
  // Do nothing.
  return 0;
}

}  // namespace ndis_testing
