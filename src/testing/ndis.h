#ifndef THIRD_PARTY_CLOUD_WINDOWS_GVNIC_TESTING_NDIS_H__
#define THIRD_PARTY_CLOUD_WINDOWS_GVNIC_TESTING_NDIS_H__

#include "base/logging.h"
#include "third_party/absl/base/attributes.h"
#include "third_party/absl/strings/str_format.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/cloud_windows_gvnic/release/testing/ndis-types.h"
#include "third_party/cloud_windows_gvnic/release/testing/windows-types.h"
#include "util/endian/endian.h"

namespace ndis_testing {

class NdisStub {
 public:
  NdisStub() : irql_(PASSIVE_LEVEL) {}
  virtual ~NdisStub() {}

  virtual void PAGED_CODE_impl(absl::string_view);
  virtual void NT_ASSERT_impl(absl::string_view expression, bool val);

  virtual void WPP_INIT_TRACING_impl(PDRIVER_OBJECT DriverObject,
                                     PUNICODE_STRING RegistryPath);
  virtual void WPP_CLEANUP_impl(PDRIVER_OBJECT DriverObject);

  virtual void NdisZeroMemory_impl(PVOID Destination, SIZE_T Length);
  virtual void NdisMoveMemory_impl(PVOID Destination, const PVOID Source,
                                   SIZE_T Length);

  virtual NDIS_STATUS NdisRetreatNetBufferDataStart_impl(
      NET_BUFFER *NetBuffer, ULONG DataOffsetDelta, ULONG DataBackFill,
      NET_BUFFER_ALLOCATE_MDL *AllocateMdlHandler);
  virtual void NdisAdvanceNetBufferDataStart_impl(
      NET_BUFFER *NetBuffer, ULONG DataOffsetDelta, BOOLEAN FreeMdl,
      NET_BUFFER_FREE_MDL *FreeMdlHandler);
  virtual void NdisMAllocateSharedMemory_impl(
      NDIS_HANDLE MiniportAdapterHandle, ULONG Length, BOOLEAN Cached,
      PVOID *VirtualAddress, PNDIS_PHYSICAL_ADDRESS PhysicalAddress);
  virtual void NdisMFreeSharedMemory_impl(
      NDIS_HANDLE MiniportAdapterHandle, ULONG Length, BOOLEAN Cached,
      PVOID VirtualAddress, NDIS_PHYSICAL_ADDRESS PhysicalAddress);

  virtual PVOID NdisAllocateMemoryWithTagPriority_impl(
      NDIS_HANDLE NdisHandle, UINT Length, ULONG Tag,
      EX_POOL_PRIORITY Priority);

  virtual PVOID NdisGetDataBuffer_impl(NET_BUFFER *NetBuffer, ULONG BytesNeeded,
                                       PVOID Storage, ULONG AlignMultiple,
                                       ULONG AlignOffset);

  virtual void NdisFreeMemoryWithTagPriority_impl(NDIS_HANDLE NdisHandle,
                                                  PVOID VirtualAddress,
                                                  ULONG Tag);
  virtual void NdisFreeMemory_impl(PVOID VirtualAddress, UINT Length,
                                   UINT MemoryFlags);

  virtual PMDL NdisAllocateMdl_impl(NDIS_HANDLE NdisHandle,
                                    PVOID VirtualAddress, UINT Length);
  virtual void NdisAdjustMdlLength_impl(PMDL Mdl, UINT Length);
  virtual void NdisFreeMdl_impl(PMDL Mdl);

  virtual PNET_BUFFER_LIST NdisAllocateNetBufferAndNetBufferList_impl(
      NDIS_HANDLE PoolHandle, USHORT ContextSize, USHORT ContextBackFill,
      PMDL MdlChain, ULONG DataOffset, SIZE_T DataLength);
  virtual void NdisFreeNetBufferList_impl(PNET_BUFFER_LIST NetBufferList);

  virtual CCHAR NdisSystemProcessorCount_impl();
  virtual ULONG NdisGroupMaxProcessorCount_impl(USHORT Group);
  virtual ULONG KeGetCurrentProcessorNumberEx_impl(
      PPROCESSOR_NUMBER ProcNumber);
  virtual ULONG KeGetProcessorIndexFromNumber_impl(
      PPROCESSOR_NUMBER ProcNumber);
  virtual NTSTATUS KeGetProcessorNumberFromIndex_impl(
      ULONG ProcIndex, PPROCESSOR_NUMBER ProcNumber);
  virtual ULONG KeQueryActiveProcessorCountEx_impl(USHORT GroupNumber);

  virtual VOID KeQueryTickCount_impl(PLARGE_INTEGER CurrentCount);

  virtual void NdisAllocateSpinLock_impl(PNDIS_SPIN_LOCK SpinLock);
  virtual void NdisFreeSpinLock_impl(PNDIS_SPIN_LOCK SpinLock);
  virtual void NdisDprAcquireSpinLock_impl(PNDIS_SPIN_LOCK SpinLock);
  virtual void NdisAcquireSpinLock_impl(PNDIS_SPIN_LOCK SpinLock);
  virtual void NdisDprReleaseSpinLock_impl(PNDIS_SPIN_LOCK SpinLock);
  virtual void NdisReleaseSpinLock_impl(PNDIS_SPIN_LOCK SpinLock);

  virtual void NdisInitializeSListHead_impl(PSLIST_HEADER SListHeader);
  virtual void NdisInterlockedPushEntrySList_impl(PSLIST_HEADER SListHeader,
                                                  PSINGLE_LIST_ENTRY SListEntry,
                                                  PNDIS_SPIN_LOCK SpinLock);
  virtual PSINGLE_LIST_ENTRY NdisInterlockedPopEntrySList_impl(
      PSLIST_HEADER SListHeader, PNDIS_SPIN_LOCK SpinLock);
  virtual void NdisInitializeListHead_impl(PLIST_ENTRY ListHead);
  virtual LONG NdisInterlockedIncrement_impl(LONG *Addend);
  virtual LONG NdisInterlockedDecrement_impl(LONG *Addend);
  virtual void NdisInterlockedInsertTailList_impl(PLIST_ENTRY ListHead,
                                                  PLIST_ENTRY ListEntry,
                                                  PNDIS_SPIN_LOCK SpinLock);
  virtual void NdisInterlockedInsertHeadList_impl(PLIST_ENTRY ListHead,
                                                  PLIST_ENTRY ListEntry,
                                                  PNDIS_SPIN_LOCK SpinLock);
  virtual PLIST_ENTRY NdisInterlockedRemoveHeadList_impl(
      PLIST_ENTRY ListHead, PNDIS_SPIN_LOCK SpinLock);

  virtual NDIS_STATUS NdisAllocateTimerObject_impl(
      NDIS_HANDLE NdisHandle, PNDIS_TIMER_CHARACTERISTICS TimerCharacteristics,
      PNDIS_HANDLE pTimerObject);
  virtual bool NdisSetCoalescableTimerObject_impl(NDIS_HANDLE TimerObject,
                                                  LARGE_INTEGER DueTime,
                                                  LONG MillisecondsPeriod,
                                                  PVOID FunctionContext,
                                                  ULONG Tolerance);
  virtual bool NdisCancelTimerObject_impl(NDIS_HANDLE TimerObject);

  virtual NDIS_STATUS NdisOpenConfigurationEx_impl(
      PNDIS_CONFIGURATION_OBJECT ConfigObject,
      PNDIS_HANDLE ConfigurationHandle);
  virtual void NdisReadConfiguration_impl(
      PNDIS_STATUS Status, PNDIS_CONFIGURATION_PARAMETER *ParameterValue,
      NDIS_HANDLE ConfigurationHandle, PNDIS_STRING Keyword,
      NDIS_PARAMETER_TYPE ParameterType);
  virtual void NdisReadNetworkAddress_impl(PNDIS_STATUS Status,
                                           PVOID *NetworkAddress,
                                           PUINT NetworkAddressLength,
                                           NDIS_HANDLE ConfigurationHandle);
  virtual void NdisCloseConfiguration_impl(NDIS_HANDLE ConfigurationHandle);

  virtual NDIS_STATUS NdisMSetMiniportAttributes_impl(
      NDIS_HANDLE NdisMiniportHandle,
      PNDIS_MINIPORT_ADAPTER_ATTRIBUTES MiniportAttributes);

  virtual PVOID MmGetSystemAddressForMdlSafe_impl(PMDL mdl,
                                                  MM_PAGE_PRIORITY priority);

  virtual NDIS_STATUS NdisMMapIoSpace_impl(
      PVOID *VirtualAddress, NDIS_HANDLE MiniportAdapterHandle,
      NDIS_PHYSICAL_ADDRESS PhysicalAddress, UINT Length);
  virtual void NdisMUnmapIoSpace_impl(NDIS_HANDLE MiniportAdapterHandle,
                                      PVOID VirtualAddress, UINT Length);

  virtual NDIS_HANDLE NdisAllocateNetBufferListPool_impl(
      NDIS_HANDLE NdisHandle, PNET_BUFFER_LIST_POOL_PARAMETERS Parameters);
  virtual void NdisFreeNetBufferListPool_impl(NDIS_HANDLE PoolHandle);

  virtual NDIS_STATUS NdisMAllocateNetBufferSGList_impl(
      NDIS_HANDLE NdisMiniportDmaHandle, PNET_BUFFER NetBuffer, PVOID Context,
      ULONG Flags, PVOID ScatterGatherListBuffer,
      ULONG ScatterGatherListBufferSize);
  virtual void NdisMFreeNetBufferSGList_impl(NDIS_HANDLE NdisMiniportDmaHandle,
                                             PSCATTER_GATHER_LIST pSGL,
                                             PNET_BUFFER NetBuffer);

  virtual NDIS_STATUS NdisMRegisterScatterGatherDma_impl(
      NDIS_HANDLE MiniportAdapterHandle,
      PNDIS_SG_DMA_DESCRIPTION DmaDescription,
      PNDIS_HANDLE NdisMiniportDmaHandle);
  virtual void NdisMDeregisterScatterGatherDma_impl(
      NDIS_HANDLE NdisMiniportDmaHandle);

  virtual NDIS_STATUS NdisMRegisterInterruptEx_impl(
      NDIS_HANDLE MiniportAdapterHandle, NDIS_HANDLE MiniportInterruptContext,
      PNDIS_MINIPORT_INTERRUPT_CHARACTERISTICS MiniportInterruptCharacteristics,
      PNDIS_HANDLE NdisInterruptHandle);
  virtual void NdisMDeregisterInterruptEx_impl(NDIS_HANDLE NdisInterruptHandle);
  virtual BOOLEAN NdisMSynchronizeWithInterruptEx_impl(
      NDIS_HANDLE NdisInterruptHandle, ULONG MessageId,
      MINIPORT_SYNCHRONIZE_INTERRUPT_HANDLER SynchronizeFunction,
      PVOID SynchronizeContext);

  virtual NDIS_STATUS NdisMRegisterMiniportDriver_impl(
      PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath,
      NDIS_HANDLE MiniportDriverContext,
      PNDIS_MINIPORT_DRIVER_CHARACTERISTICS MiniportDriverCharacteristics,
      PNDIS_HANDLE NdisMiniportDriverHandle);
  virtual void NdisMDeregisterMiniportDriver_impl(
      NDIS_HANDLE NdisMiniportDriverHandle);
  virtual NDIS_STATUS NdisSetOptionalHandlers_impl(
      NDIS_HANDLE NdisHandle, PNDIS_DRIVER_OPTIONAL_HANDLERS OptionalHandlers);

  virtual void NdisInitializeNPagedLookasideList_impl(
      PNPAGED_LOOKASIDE_LIST Lookaside, PALLOCATE_FUNCTION Allocate,
      PFREE_FUNCTION Free, ULONG Flags, SIZE_T Size, ULONG Tag, USHORT Depth);
  virtual void NdisDeleteNPagedLookasideList_impl(
      PNPAGED_LOOKASIDE_LIST Lookaside);
  virtual PVOID NdisAllocateFromNPagedLookasideList_impl(
      PNPAGED_LOOKASIDE_LIST Lookaside);
  virtual void NdisFreeToNPagedLookasideList_impl(
      PNPAGED_LOOKASIDE_LIST Lookaside, PVOID buffer);

  virtual void NdisMSendNetBufferListsComplete_impl(
      NDIS_HANDLE MiniportAdapterHandle, PNET_BUFFER_LIST NetBufferList,
      ULONG SendCompleteFlags);
  virtual void NdisMIndicateReceiveNetBufferLists_impl(
      NDIS_HANDLE MiniportAdapterHandle, PNET_BUFFER_LIST NetBufferList,
      NDIS_PORT_NUMBER PortNumber, ULONG NumberOfNetBufferLists,
      ULONG ReceiveFlags);
  virtual void NdisMIndicateStatusEx_impl(
      NDIS_HANDLE MiniportAdapterHandle,
      PNDIS_STATUS_INDICATION StatusIndication);

  virtual void NdisMResetMiniport_impl(NDIS_HANDLE MiniportAdapterHandle);

  virtual void NdisInitializeString_impl(PNDIS_STRING Destination,
                                         PUCHAR Source);

  virtual void NdisMSleep_impl(ULONG MicrosecondsToSleep);
  virtual void NdisWriteErrorLogEntry_impl(NDIS_HANDLE NdisAdapterHandle,
                                           NDIS_ERROR_CODE ErrorCode,
                                           ULONG NumberOfErrorValues,
                                           ULONG Val1, ULONG Val2);

  virtual NDIS_STATUS NdisGetRssProcessorInformation_impl(
      NDIS_HANDLE NdisHandle, PNDIS_RSS_PROCESSOR_INFO RssProcessorInfo,
      PSIZE_T Size);
  virtual NDIS_STATUS NdisMConfigMSIXTableEntry_impl(
      NDIS_HANDLE NdisMiniportHandle,
      PNDIS_MSIX_CONFIG_PARAMETERS MSIXConfigParameters);

  virtual void NdisWriteRegisterUlong_impl(PULONG addr, ULONG val);

  virtual NDIS_HANDLE NdisAllocateIoWorkItem_impl(NDIS_HANDLE NdisObjectHandle);
  virtual void NdisQueueIoWorkItem_impl(NDIS_HANDLE NdisIoWorkItemHandle,
                                        NDIS_IO_WORKITEM_ROUTINE Routine,
                                        PVOID WorkItemContext);
  virtual void NdisFreeIoWorkItem_impl(NDIS_HANDLE NdisIoWorkItemHandle);

  virtual void NdisMResetComplete_impl(NDIS_HANDLE MiniportAdapterHandle,
                                       NDIS_STATUS Status,
                                       BOOLEAN AddressingReset);

  virtual KAFFINITY NdisMQueueDpcEx_impl(NDIS_HANDLE NdisInterruptHandle,
                                         ULONG MessageId,
                                         PGROUP_AFFINITY TargetProcessors,
                                         PVOID MiniportDpcContext);

  KIRQL irql_;
};

// The NDIS mock object holds mock expectations, and is called by the mock NDIS
// framework. Since our goal is to mock C-style functions, we need to have one
// static object shared by all test cases in a test target, and each test case
// must create and destroy the mock to evaluate whether the expectations were
// satisfied.
extern NdisStub *ndis_mock_object;

}  // namespace ndis_testing

// Logging bits defined in trace.h and produced by the WPP preprocessor.
enum {
  TRACE_DRIVER = 0x1,
  TRACE_TX = 0x2,
  TRACE_RX = 0x4,
  TRACE_ISR = 0x8,
};

// Mock for WPP macros that are generated in MSBUILD. They are required to be
// implemented here to run on google3.
#define DEBUGP(level, ...) \
  LOG(INFO) << #level << ": " << absl::StrFormat(__VA_ARGS__)
#define DEBUGP_CRITICAL(flag, ...) \
  LOG(INFO) << "CRITICAL: " << absl::StrFormat(__VA_ARGS__)
#define DEBUGP_ERROR(flag, ...) \
  LOG(INFO) << "ERROR: " << absl::StrFormat(__VA_ARGS__)
#define DEBUGP_WARNING(flag, ...) \
  LOG(INFO) << "WARNING: " << absl::StrFormat(__VA_ARGS__)
#define DEBUGP_INFO(flag, ...) \
  LOG(INFO) << "INFO: " << absl::StrFormat(__VA_ARGS__)
#define DEBUGP_VERBOSE(flag, ...) \
  LOG(INFO) << "VERBOSE: " << absl::StrFormat(__VA_ARGS__)
#define DEBUGP_ENTRY(flag) LOG(INFO) << __FUNCTION__ << "--->";
#define DEBUGP_EXIT(flag) LOG(INFO) << __FUNCTION__ << "<---";

// Microsoft's min() and max() are more lenient than ours about comparing
// different types.
template <typename A, typename B>
auto min(A a, B b) {
  return a < b ? a : b;
}
template <typename A, typename B>
auto max(A a, B b) {
  return a > b ? a : b;
}

// Unit tests won't actually access data via the physical address, so when
// functions require a physical address we will use the virtual address
// with a known offset. This isn't part of the NDIS framework, but is declared
// here for use by the stub when creating default actions.
constexpr uint32 kPhysicalAddressOffset = 0x1000;

// Enables some of the driver's additional validation in unit tests. Checked
// builds (when building a driver for testing in a VIT) always have this set.
#define DBG 1

#define __declspec(spec) spec
#define _Use_decl_annotations_
#define __sdv_save_adapter_context(a)
#define align(size)
#define _Analysis_assume_(condition)
#define _IRQL_raises_(level)
#define _IRQL_saves_global_(kind, param)
#define _IRQL_restores_global_(kind, param)
#define _IRQL_requires_(level)
#define _IRQL_requires_min_(level)
#define _IRQL_requires_max_(level)
#define _Acquires_lock_(lock)
#define _Releases_lock_(lock)
#define _Requires_lock_not_held_(lock)
#define _Requires_lock_held_(lock)
#define _Guarded_by_(lock)
#define _IRQL_requires_same_
#define __fallthrough ABSL_FALLTHROUGH_INTENDED
#define UNREFERENCED_PARAMETER(param)
#define FIELD_OFFSET(t, f) offsetof(t, f)
#define ETH_IS_BROADCAST(Address)               \
  ((((PUCHAR)(Address))[0] == ((UCHAR)0xff)) && \
   (((PUCHAR)(Address))[1] == ((UCHAR)0xff)))
#define ETH_IS_MULTICAST(Address) \
  (BOOLEAN)(((PUCHAR)(Address))[0] & ((UCHAR)0x01))
#define IN
#define _In_
#define OUT
#define _Out_
#define CONTAINING_RECORD(Address, Type, Field) \
  ((Type *)(((ULONG_PTR)Address) - FIELD_OFFSET(Type, Field)))

// Stubbed C-style free functions that will call into the NDIS object for
// mocking.
#define PAGED_CODE() ndis_testing::ndis_mock_object->PAGED_CODE_impl(__func__)
#define NT_ASSERT(val) ndis_testing::ndis_mock_object->NT_ASSERT_impl(#val, val)
#define NT_VERIFY(val) NT_ASSERT(val)
#define WPP_INIT_TRACING(...) \
  ndis_testing::ndis_mock_object->WPP_INIT_TRACING_impl(__VA_ARGS__)
#define WPP_CLEANUP(...) \
  ndis_testing::ndis_mock_object->WPP_CLEANUP_impl(__VA_ARGS__)

#define KeGetCurrentIrql() ndis_testing::ndis_mock_object->irql_
#define NDIS_RAISE_IRQL_TO_DISPATCH(irql)                   \
  {                                                         \
    *irql = ndis_testing::ndis_mock_object->irql_;          \
    ndis_testing::ndis_mock_object->irql_ = DISPATCH_LEVEL; \
  }
#define NDIS_LOWER_IRQL(old_irql, current_irql) \
  ndis_testing::ndis_mock_object->irql_ = old_irql

#define KeMemoryBarrier()
#define DbgBreakPoint()
#define RtlUshortByteSwap(val) gbswap_16(val)
#define RtlUlongByteSwap(val) gbswap_32(val)
#define RtlUlonglongByteSwap(val) gbswap_64(val)

#define NdisZeroMemory(...) \
  ndis_testing::ndis_mock_object->NdisZeroMemory_impl(__VA_ARGS__)
#define NdisMoveMemory(dst, src, len)                                         \
  ndis_testing::ndis_mock_object->NdisMoveMemory_impl((PVOID)dst, (PVOID)src, \
                                                      len)

#define NdisRetreatNetBufferDataStart(...)                            \
  ndis_testing::ndis_mock_object->NdisRetreatNetBufferDataStart_impl( \
      __VA_ARGS__)
#define NdisAdvanceNetBufferDataStart(...)                            \
  ndis_testing::ndis_mock_object->NdisAdvanceNetBufferDataStart_impl( \
      __VA_ARGS__)
#define NdisMAllocateSharedMemory(...) \
  ndis_testing::ndis_mock_object->NdisMAllocateSharedMemory_impl(__VA_ARGS__)
#define NdisAllocateMemoryWithTagPriority(...)                            \
  ndis_testing::ndis_mock_object->NdisAllocateMemoryWithTagPriority_impl( \
      __VA_ARGS__)
#define NdisGetDataBuffer(...) \
  ndis_testing::ndis_mock_object->NdisGetDataBuffer_impl(__VA_ARGS__)
#define NdisFreeMemoryWithTagPriority(...)                            \
  ndis_testing::ndis_mock_object->NdisFreeMemoryWithTagPriority_impl( \
      __VA_ARGS__)
#define NdisAllocateNetBufferListPool(...)                            \
  ndis_testing::ndis_mock_object->NdisAllocateNetBufferListPool_impl( \
      __VA_ARGS__)
#define NdisMAllocateNetBufferSGList(...) \
  ndis_testing::ndis_mock_object->NdisMAllocateNetBufferSGList_impl(__VA_ARGS__)
#define NdisAllocateMdl(...) \
  ndis_testing::ndis_mock_object->NdisAllocateMdl_impl(__VA_ARGS__)
#define NdisAdjustMdlLength(...) \
  ndis_testing::ndis_mock_object->NdisAdjustMdlLength_impl(__VA_ARGS__)
#define NdisAllocateNetBufferAndNetBufferList(...)                            \
  ndis_testing::ndis_mock_object->NdisAllocateNetBufferAndNetBufferList_impl( \
      __VA_ARGS__)

#define NdisMFreeSharedMemory(...) \
  ndis_testing::ndis_mock_object->NdisMFreeSharedMemory_impl(__VA_ARGS__)
#define NdisFreeMemory(...) \
  ndis_testing::ndis_mock_object->NdisFreeMemory_impl(__VA_ARGS__)
#define NdisFreeMdl(...) \
  ndis_testing::ndis_mock_object->NdisFreeMdl_impl(__VA_ARGS__)
#define NdisMFreeNetBufferSGList(...) \
  ndis_testing::ndis_mock_object->NdisMFreeNetBufferSGList_impl(__VA_ARGS__)
#define NdisFreeNetBufferList(...) \
  ndis_testing::ndis_mock_object->NdisFreeNetBufferList_impl(__VA_ARGS__)

#define NdisMSendNetBufferListsComplete(...)                            \
  ndis_testing::ndis_mock_object->NdisMSendNetBufferListsComplete_impl( \
      __VA_ARGS__)
#define NdisMIndicateStatusEx(...) \
  ndis_testing::ndis_mock_object->NdisMIndicateStatusEx_impl(__VA_ARGS__)
#define NdisMIndicateReceiveNetBufferLists(...)                            \
  ndis_testing::ndis_mock_object->NdisMIndicateReceiveNetBufferLists_impl( \
      __VA_ARGS__)
#define NdisMResetMiniport(...) \
  ndis_testing::ndis_mock_object->NdisMResetMiniport_impl(__VA_ARGS__)

#define MmGetMdlByteCount(_Mdl) ((_Mdl)->ByteCount)
#define NdisQueryMdl(_Mdl, _VirtualAddress, _Length, _Priority)       \
  {                                                                   \
    *_VirtualAddress = MmGetSystemAddressForMdlSafe(_Mdl, _Priority); \
    *_Length = MmGetMdlByteCount(_Mdl);                               \
  }
#define MmGetSystemAddressForMdlSafe(...) \
  ndis_testing::ndis_mock_object->MmGetSystemAddressForMdlSafe_impl(__VA_ARGS__)

#define NdisMMapIoSpace(...) \
  ndis_testing::ndis_mock_object->NdisMMapIoSpace_impl(__VA_ARGS__)
#define NdisMUnmapIoSpace(...) \
  ndis_testing::ndis_mock_object->NdisMUnmapIoSpace_impl(__VA_ARGS__)
#define NdisFreeNetBufferListPool(...) \
  ndis_testing::ndis_mock_object->NdisFreeNetBufferListPool_impl(__VA_ARGS__)
#define NdisMDeregisterScatterGatherDma(...)                            \
  ndis_testing::ndis_mock_object->NdisMDeregisterScatterGatherDma_impl( \
      __VA_ARGS__)
#define NdisMDeregisterInterruptEx(...) \
  ndis_testing::ndis_mock_object->NdisMDeregisterInterruptEx_impl(__VA_ARGS__)
#define NdisMRegisterScatterGatherDma(...)                            \
  ndis_testing::ndis_mock_object->NdisMRegisterScatterGatherDma_impl( \
      __VA_ARGS__)
#define NdisMRegisterInterruptEx(...) \
  ndis_testing::ndis_mock_object->NdisMRegisterInterruptEx_impl(__VA_ARGS__)
#define NdisMSynchronizeWithInterruptEx(...)                            \
  ndis_testing::ndis_mock_object->NdisMSynchronizeWithInterruptEx_impl( \
      __VA_ARGS__)

#define NdisMRegisterMiniportDriver(...) \
  ndis_testing::ndis_mock_object->NdisMRegisterMiniportDriver_impl(__VA_ARGS__)
#define NdisMDeregisterMiniportDriver(...)                            \
  ndis_testing::ndis_mock_object->NdisMDeregisterMiniportDriver_impl( \
      __VA_ARGS__)
#define NdisSetOptionalHandlers(...) \
  ndis_testing::ndis_mock_object->NdisSetOptionalHandlers_impl(__VA_ARGS__)

#define KeGetCurrentProcessorNumberEx(...)                            \
  ndis_testing::ndis_mock_object->KeGetCurrentProcessorNumberEx_impl( \
      __VA_ARGS__)
#define KeGetProcessorIndexFromNumber(...)                            \
  ndis_testing::ndis_mock_object->KeGetProcessorIndexFromNumber_impl( \
      __VA_ARGS__)
#define KeGetProcessorNumberFromIndex(...)                            \
  ndis_testing::ndis_mock_object->KeGetProcessorNumberFromIndex_impl( \
      __VA_ARGS__)
#define KeQueryActiveProcessorCountEx(...)                            \
  ndis_testing::ndis_mock_object->KeQueryActiveProcessorCountEx_impl( \
      __VA_ARGS__)
#define KeQueryTickCount(...) \
  ndis_testing::ndis_mock_object->KeQueryTickCount_impl(__VA_ARGS__)
#define NdisSystemProcessorCount() \
  ndis_testing::ndis_mock_object->NdisSystemProcessorCount_impl()
#define NdisGroupActiveProcessorCount(...) \
  ndis_testing::ndis_mock_object->NdisGroupMaxProcessorCount_impl(__VA_ARGS__)

#define NdisInitializeString(...) \
  ndis_testing::ndis_mock_object->NdisInitializeString_impl(__VA_ARGS__)
#define NdisFreeString(string) free(string.Buffer)

#define NdisOpenConfigurationEx(...) \
  ndis_testing::ndis_mock_object->NdisOpenConfigurationEx_impl(__VA_ARGS__)
#define NdisReadConfiguration(...) \
  ndis_testing::ndis_mock_object->NdisReadConfiguration_impl(__VA_ARGS__)
#define NdisReadNetworkAddress(...) \
  ndis_testing::ndis_mock_object->NdisReadNetworkAddress_impl(__VA_ARGS__)
#define NdisCloseConfiguration(...) \
  ndis_testing::ndis_mock_object->NdisCloseConfiguration_impl(__VA_ARGS__)

#define NdisMSetMiniportAttributes(...) \
  ndis_testing::ndis_mock_object->NdisMSetMiniportAttributes_impl(__VA_ARGS__)

#define NdisAllocateSpinLock(...) \
  ndis_testing::ndis_mock_object->NdisAllocateSpinLock_impl(__VA_ARGS__)
#define NdisFreeSpinLock(...) \
  ndis_testing::ndis_mock_object->NdisFreeSpinLock_impl(__VA_ARGS__)
#define NdisDprAcquireSpinLock(...) \
  ndis_testing::ndis_mock_object->NdisDprAcquireSpinLock_impl(__VA_ARGS__)
#define NdisAcquireSpinLock(...) \
  ndis_testing::ndis_mock_object->NdisAcquireSpinLock_impl(__VA_ARGS__)
#define NdisDprReleaseSpinLock(...) \
  ndis_testing::ndis_mock_object->NdisDprReleaseSpinLock_impl(__VA_ARGS__)
#define NdisReleaseSpinLock(...) \
  ndis_testing::ndis_mock_object->NdisReleaseSpinLock_impl(__VA_ARGS__)

#define NdisInitializeSListHead(...) \
  ndis_testing::ndis_mock_object->NdisInitializeSListHead_impl(__VA_ARGS__)
#define NdisInterlockedPushEntrySList(...)                            \
  ndis_testing::ndis_mock_object->NdisInterlockedPushEntrySList_impl( \
      __VA_ARGS__)
#define NdisInterlockedPopEntrySList(...) \
  ndis_testing::ndis_mock_object->NdisInterlockedPopEntrySList_impl(__VA_ARGS__)
#define NdisInitializeListHead(...) \
  ndis_testing::ndis_mock_object->NdisInitializeListHead_impl(__VA_ARGS__)
#define NdisInterlockedIncrement(...) \
  ndis_testing::ndis_mock_object->NdisInterlockedIncrement_impl(__VA_ARGS__)
#define NdisInterlockedDecrement(...) \
  ndis_testing::ndis_mock_object->NdisInterlockedDecrement_impl(__VA_ARGS__)
#define NdisInterlockedInsertTailList(...)                            \
  ndis_testing::ndis_mock_object->NdisInterlockedInsertTailList_impl( \
      __VA_ARGS__)
#define NdisInterlockedInsertHeadList(...)                            \
  ndis_testing::ndis_mock_object->NdisInterlockedInsertHeadList_impl( \
      __VA_ARGS__)
#define NdisInterlockedRemoveHeadList(...)                            \
  ndis_testing::ndis_mock_object->NdisInterlockedRemoveHeadList_impl( \
      __VA_ARGS__)

#define NdisAllocateTimerObject(...) \
  ndis_testing::ndis_mock_object->NdisAllocateTimerObject_impl(__VA_ARGS__)
#define NdisFreeTimerObject(...)
#define NdisSetCoalescableTimerObject(...)                            \
  ndis_testing::ndis_mock_object->NdisSetCoalescableTimerObject_impl( \
      __VA_ARGS__)
#define NdisCancelTimerObject(...) \
  ndis_testing::ndis_mock_object->NdisCancelTimerObject_impl(__VA_ARGS__)

#define NdisInitializeNPagedLookasideList(...)                            \
  ndis_testing::ndis_mock_object->NdisInitializeNPagedLookasideList_impl( \
      __VA_ARGS__)
#define NdisDeleteNPagedLookasideList(...)                            \
  ndis_testing::ndis_mock_object->NdisDeleteNPagedLookasideList_impl( \
      __VA_ARGS__)
#define NdisAllocateFromNPagedLookasideList(...)                            \
  ndis_testing::ndis_mock_object->NdisAllocateFromNPagedLookasideList_impl( \
      __VA_ARGS__)
#define NdisFreeToNPagedLookasideList(...)                            \
  ndis_testing::ndis_mock_object->NdisFreeToNPagedLookasideList_impl( \
      __VA_ARGS__)

#define NdisReadRegisterUchar(register, data) *(data) = *((PUCHAR)(register))
#define NdisReadRegisterUshort(register, data) *(data) = *((PUSHORT)(register))
#define NdisReadRegisterUlong(register, data) *(data) = *((PULONG)(register))
#define NdisWriteRegisterUchar(register, data) *(register) = (data)
#define NdisWriteRegisterUshort(register, data) *(register) = (data)
#define NdisWriteRegisterUlong(...) \
  ndis_testing::ndis_mock_object->NdisWriteRegisterUlong_impl(__VA_ARGS__)

#define NdisMSleep(...) \
  ndis_testing::ndis_mock_object->NdisMSleep_impl(__VA_ARGS__)
#define NdisWriteErrorLogEntry(...) \
  ndis_testing::ndis_mock_object->NdisWriteErrorLogEntry_impl(__VA_ARGS__)

#define NdisGetRssProcessorInformation(...)                            \
  ndis_testing::ndis_mock_object->NdisGetRssProcessorInformation_impl( \
      __VA_ARGS__)

#define NdisMConfigMSIXTableEntry(...) \
  ndis_testing::ndis_mock_object->NdisMConfigMSIXTableEntry_impl(__VA_ARGS__)

#define NdisAllocateIoWorkItem(...) \
  ndis_testing::ndis_mock_object->NdisAllocateIoWorkItem_impl(__VA_ARGS__)
#define NdisQueueIoWorkItem(...) \
  ndis_testing::ndis_mock_object->NdisQueueIoWorkItem_impl(__VA_ARGS__)
#define NdisFreeIoWorkItem(...) \
  ndis_testing::ndis_mock_object->NdisFreeIoWorkItem_impl(__VA_ARGS__)

#define NdisMResetComplete(...) \
  ndis_testing::ndis_mock_object->NdisMResetComplete_impl(__VA_ARGS__)
#define NdisMQueueDpcEx(...) \
  ndis_testing::ndis_mock_object->NdisMQueueDpcEx_impl(__VA_ARGS__)

#define InterlockedIncrement(val) ++(*val)
#define InterlockedDecrement(val) --(*val)
#define InterlockedIncrement16(val) InterlockedIncrement(val)
#define InterlockedDecrement16(val) InterlockedDecrement(val)
#define InterlockedAdd(Addend, val) ((*Addend) += val)

#define NT_ERROR(_Status) ((0xC0000000 <= _Status) && (_Status <= 0xFFFFFFFF))
#define NT_WARNING(_Status) ((0x80000000 <= _Status) && (_Status <= 0xBFFFFFFF))
#define NT_INFORMATION(_Status) \
  ((0x40000000 <= _Status) && (_Status <= 0x7FFFFFFF))
#define NT_SUCCESS(_Status) ((_Status <= 0x3FFFFFFF) || NT_INFORMATION(_Status))

#define INVALID_PROCESSOR_INDEX (-1)

#define DEFINE_GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8)

static __inline LONG InterlockedExchange(LONG *a, LONG b) {
  LONG ret = *a;
  *a = b;
  return ret;
}

#define UlongToPtr(ul) ((VOID *)(ULONG_PTR)((ULONG)ul))
#define PtrToUlong(p) ((ULONG)(ULONG_PTR)(p))

#define NET_BUFFER_LIST_GET_HASH_VALUE(_NBL) \
  { PtrToUlong(NET_BUFFER_LIST_INFO(_NBL, NetBufferListHashValue)) }

#define NET_BUFFER_LIST_SET_HASH_VALUE(_NBL, _HashValue) \
  (NET_BUFFER_LIST_INFO(_NBL, NetBufferListHashValue) = UlongToPtr(_HashValue))

#define NET_BUFFER_LIST_SET_HASH_FUNCTION(_NBL, _HashFunction)           \
  (NET_BUFFER_LIST_INFO(_NBL, NetBufferListHashInfo) = UlongToPtr(       \
       ((PtrToUlong(NET_BUFFER_LIST_INFO(_NBL, NetBufferListHashInfo)) & \
         (~NDIS_HASH_FUNCTION_MASK)) |                                   \
        ((_HashFunction) & (NDIS_HASH_FUNCTION_MASK)))))

#define NET_BUFFER_LIST_SET_HASH_TYPE(_NBL, _HashType)                   \
  (NET_BUFFER_LIST_INFO(_NBL, NetBufferListHashInfo) = UlongToPtr(       \
       ((PtrToUlong(NET_BUFFER_LIST_INFO(_NBL, NetBufferListHashInfo)) & \
         (~NDIS_HASH_TYPE_MASK)) |                                       \
        ((_HashType) & (NDIS_HASH_TYPE_MASK)))));

#define ETH_COPY_NETWORK_ADDRESS(_D, _S)                                 \
  {                                                                      \
    *((ULONG *)(_D)) = *((ULONG *)(_S));                                 \
    *((USHORT *)((UCHAR *)(_D) + 4)) = *((USHORT *)((UCHAR *)(_S) + 4)); \
  }

#define NDIS_MDL_LINKAGE(_mdl) _mdl->Next

#endif  // THIRD_PARTY_CLOUD_WINDOWS_GVNIC_TESTING_NDIS_H__
