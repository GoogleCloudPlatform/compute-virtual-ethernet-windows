#ifndef THIRD_PARTY_CLOUD_WINDOWS_GVNIC_RELEASE_TESTING_GVNIC_TEST_FIXTURE_H_
#define THIRD_PARTY_CLOUD_WINDOWS_GVNIC_RELEASE_TESTING_GVNIC_TEST_FIXTURE_H_

#include <memory>
#include <type_traits>

// These Microsoft compiler macro hacks make gMock complain when building with
// --config=no_modules.
#undef __declspec

#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"

#define __declspec(a)

#include "third_party/absl/strings/string_view.h"
#include "third_party/cloud_windows_gvnic/release/abi.h"
#include "third_party/cloud_windows_gvnic/release/adapter_context.h"
#include "third_party/cloud_windows_gvnic/release/adapter_resource.h"
#include "third_party/cloud_windows_gvnic/release/adapter_statistics.h"
#include "third_party/cloud_windows_gvnic/release/ndis_memory.h"
#include "third_party/cloud_windows_gvnic/release/ring_base.h"
#include "third_party/cloud_windows_gvnic/release/testing/ndis-mock.h"
#include "third_party/cloud_windows_gvnic/release/testing/ndis.h"

namespace ndis_testing {

class GvnicTestFixture : public ::testing::Test {
 public:
  void SetUp() override {
    // These tests use a global mock object, so they are not thread (or shard)
    // safe.
    ASSERT_EQ(1, Int32FromEnv("TEST_TOTAL_SHARDS", 1));

    ndis_mock_object_ = std::make_unique<testing::NiceMock<NdisMock>>();
    ndis_mock_object = ndis_mock_object_.get();
    wdm_mock_object_ = std::make_unique<testing::NiceMock<NdisMock>>();
    wdm_mock_object = wdm_mock_object_.get();
    ntstrsafe_mock_object_ = std::make_unique<testing::NiceMock<NdisMock>>();
    ntstrsafe_mock_object = ntstrsafe_mock_object_.get();

    // Zero registers.
    memset(&bar0_, 0, sizeof(GvnicDeviceConfig));
    bar1_ = 0;
    bar2_ = 0;
  }

  NdisMock& GetMock() { return *ndis_mock_object_; }
  NdisMock& GetWMock() { return *wdm_mock_object_; }
  NdisMock& GetStrMock() { return *ntstrsafe_mock_object_; }

 protected:
  uint32 GetDoorbell(const RingBase& ring) {
    const uint32 doorbell_index = RtlUlongByteSwap(
        reinterpret_cast<QueueResources*>(
            ring.ResourcesPhysicalAddress().QuadPart - kPhysicalAddressOffset)
            ->doorbell_index);
    return RtlUlongByteSwap(reinterpret_cast<uint32*>(&bar2_)[doorbell_index]);
  }

  uint32_t GetDoorbellLE(const RingBase& ring) {
    const uint32_t doorbell_index = RtlUlongByteSwap(
        reinterpret_cast<QueueResources*>(
            ring.ResourcesPhysicalAddress().QuadPart - kPhysicalAddressOffset)
            ->doorbell_index);
    return reinterpret_cast<uint32_t*>(&bar2_)[doorbell_index];
  }

  void IntializeAdapterStatistics() {
    adapter_statistics_ = std::make_unique<NDIS_STATISTICS_INFO>();
  }

  NDIS_STATUS InitializeAdapterResources() {
    adapter_resources_ = std::make_unique<AdapterResources>();
    return InitializeAdapterResources(adapter_resources_.get());
  }

  PNDIS_RESOURCE_LIST GetInitializedNdisResourceList() {
    size_t resource_list_size = sizeof(CM_PARTIAL_RESOURCE_LIST) +
                                sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR) * 3;
    PNDIS_RESOURCE_LIST resource_list =
        static_cast<PNDIS_RESOURCE_LIST>(calloc(1, resource_list_size));

    resource_list->Count = 4;

    // The "physical" address is the virtual address plus a known offset.
    resource_list->PartialDescriptors[0].Type = CmResourceTypeMemory;
    resource_list->PartialDescriptors[0].u.Memory.Start.QuadPart =
        reinterpret_cast<LONGLONG>(&bar0_) + kPhysicalAddressOffset;
    resource_list->PartialDescriptors[0].u.Memory.Length =
        sizeof(GvnicDeviceConfig);

    resource_list->PartialDescriptors[1].Type = CmResourceTypeMemory;
    resource_list->PartialDescriptors[1].u.Memory.Start.QuadPart =
        reinterpret_cast<LONGLONG>(&bar1_) + kPhysicalAddressOffset;
    resource_list->PartialDescriptors[1].u.Memory.Length = sizeof(uint64);

    resource_list->PartialDescriptors[2].Type = CmResourceTypeMemory;
    resource_list->PartialDescriptors[2].u.Memory.Start.QuadPart =
        reinterpret_cast<LONGLONG>(&bar2_) + kPhysicalAddressOffset;
    resource_list->PartialDescriptors[2].u.Memory.Length = sizeof(uint64);

    resource_list->PartialDescriptors[3].Type = CmResourceTypeInterrupt;
    resource_list->PartialDescriptors[3].Flags = CM_RESOURCE_INTERRUPT_MESSAGE;

    return resource_list;
  }

  NDIS_STATUS InitializeAdapterResources(AdapterResources* resources) {
    // Descriptors for 3 registers, and one interrupt.
    PNDIS_RESOURCE_LIST resource_list = GetInitializedNdisResourceList();
    NDIS_STATUS status = resources->Initialize(
        kNdisHandle, kNdisHandle, resource_list, /*adapter_context=*/nullptr);

    free(resource_list);
    return status;
  }

  void AutoCompleteAdminQueueCommands() {
    EXPECT_CALL(GetMock(),
                NdisWriteRegisterUlong_impl(::testing::_, ::testing::_))
        .WillRepeatedly([this](PULONG addr, ULONG val) {
          *addr = val;
          if (addr == &bar0_.admin_queue_doorbell) {
            // If this was an admin queue doorbell write, we want to complete
            // what was added to the queue as well.
            AdminQueueCommand* command =
                GetAdminCommandAtIndex(RtlUlongByteSwap(val) - 1);
            command->status = RtlUlongByteSwap(kAdminQueueCommandPassed);

            switch (RtlUlongByteSwap(command->opcode)) {
              case kDescribeDevice: {
                DeviceDescriptor* device_descriptor =
                    reinterpret_cast<DeviceDescriptor*>(
                        RtlUlonglongByteSwap(command->describe_device
                                                 .device_descriptor_address) -
                        kPhysicalAddressOffset);
                device_descriptor->tx_queue_size = RtlUshortByteSwap(2);
                device_descriptor->rx_queue_size = RtlUshortByteSwap(4);
                device_descriptor->default_num_queues = RtlUshortByteSwap(2);

                // When multiplied by the descriptor size, this must be a
                // multiple of PAGE_SIZE.
                device_descriptor->tx_queue_size = RtlUshortByteSwap(256);
                device_descriptor->rx_queue_size = RtlUshortByteSwap(64);
                break;
              }
              case kSetWindowsRssParameters: {
                uint32 num_entries = RtlUshortByteSwap(
                    command->set_rss_parameters.queue_indirection_table_size);
                uint32* table = reinterpret_cast<uint32*>(
                    RtlUlonglongByteSwap(command->set_rss_parameters
                                             .queue_indirection_table_addr) -
                    kPhysicalAddressOffset);
                for (uint32 i = 0; i < num_entries; i++) {
                  captured_rss_indirection_table_.push_back(
                      RtlUlongByteSwap(table[i]));
                }
                break;
              }
              default:
                // Do nothing.
                break;
            }

            bar0_.admin_queue_event_counter = val;
          }
        });
  }

  AdminQueueCommand* GetAdminCommandAtIndex(UINT32 idx) {
    // Try and find the admin queue. In real systems this would be page aligned
    // physical memory at an address less than 52 bits, but since we generate
    // this from a 64 bit virtual address we could have truncated it.
    uint32 truncated_address = RtlUlongByteSwap(bar0_.admin_queue_pfn)
                               << PAGE_SHIFT;
    for (const auto& address :
         ndis_mock_object_->physical_to_virtual_addresses_) {
      if (static_cast<uint32>(address.first) == truncated_address) {
        AdminQueueCommand* queue =
            reinterpret_cast<AdminQueueCommand*>(address.second);
        return &queue[idx % (PAGE_SIZE / kAdminQeueueCommandSize)];
      }
    }

    return nullptr;
  }

  // Returns a pointer to the zero indexed device option. This does no bounds
  // checking, so make sure it's a valid index.
  DeviceOption* GetDeviceOptionAtIndex(DeviceDescriptor* desc, uint32 index) {
    DeviceOption* option = reinterpret_cast<DeviceOption*>(desc + 1);
    for (uint32 i = 0; i != index; i++) {
      option = reinterpret_cast<DeviceOption*>(
          reinterpret_cast<PUCHAR>(option) + sizeof(DeviceOption) +
          RtlUshortByteSwap(option->option_length));
    }

    return option;
  }

  // NOTE: This should be the first object declared in this test fixture so
  // that its destructor is called last. Other objects may call into the mock
  // NDIS framework in their destructors.
  std::unique_ptr<testing::NiceMock<NdisMock>> ndis_mock_object_;
  std::unique_ptr<testing::NiceMock<NdisMock>> wdm_mock_object_;
  std::unique_ptr<testing::NiceMock<NdisMock>> ntstrsafe_mock_object_;

  // Default registers.
  GvnicDeviceConfig bar0_;
  uint64 bar1_;
  uint64 bar2_;  // Room for two doorbells.

  // Contains the CPU->slice mapping sent to the device. Only populated if
  // AutoCompleteAdminQueueCommands() was used.
  std::vector<uint8> captured_rss_indirection_table_;

  // This is an arbitrary memory value that doesn't point to owned memory. This
  // can be passed to functions that require an NDIS_HANDLE, but shouldn't be
  // dereferenced.
  const NDIS_HANDLE kNdisHandle = reinterpret_cast<void*>(0xA5A5A5A5);

  std::unique_ptr<AdapterResources> adapter_resources_;
  std::unique_ptr<NDIS_STATISTICS_INFO> adapter_statistics_;
};

// Deleter calls to allow classes that inherit from NdisPlacementAlloc to be
// able to use std::unique_ptr<T,NdisPlacementAllocDeleter>  to manage memory.
//
// std::unique_ptr<T> requires the delete function for class T to be available
// as it is called when the std::unique_ptr is deconstructed.
//
// As this is deleted for NdisPlacementAlloc classes to ensure that they are
// never allocated from the heap, this Deleter is required to allow for the
// NdisPlacementAlloc::Destroy to be called instead.

struct NdisPlacementAllocDeleter {
  template <typename T>
  inline void operator()(T* ptr) const {
    T::Destroy(ptr, reinterpret_cast<void*>(0xA5A5A5A5));
  }
};

}  // namespace ndis_testing

#endif  // THIRD_PARTY_CLOUD_WINDOWS_GVNIC_RELEASE_TESTING_GVNIC_TEST_FIXTURE_H_
