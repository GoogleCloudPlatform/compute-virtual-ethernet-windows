/*
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ADAPTER_RESOURCE_H_
#define ADAPTER_RESOURCE_H_

#include <ndis.h>

constexpr int kGvnicBarCount = 3;
constexpr int kConfigStatusRegister = 0;
constexpr int kDoorbellRegister = 2;

struct BaseAddressRegister {
  PHYSICAL_ADDRESS start;
  ULONG length;
  PVOID virtual_address;
};

// Class for holding resources allocated by the driver. Including:
// - interrupt
// - DMA
// - bufferlist_pool
class AdapterResources final {
 public:
  AdapterResources()
      : driver_handle_(nullptr),
        miniport_handle_(nullptr),
        dma_handle_(nullptr),
        interrupt_handle_(nullptr),
        buffer_list_pool_(nullptr),
        recommended_sg_list_size_(0) {}
  ~AdapterResources();

  // Not copyable or movable
  AdapterResources(const AdapterResources&) = delete;
  AdapterResources& operator=(const AdapterResources&) = delete;

  NDIS_STATUS Initialize(NDIS_HANDLE driver_handle, NDIS_HANDLE miniport_handle,
                         PNDIS_RESOURCE_LIST ndis_resource_list,
                         PVOID adapter_context);

  void ReadRegister(int bar_number, ULONG offset, PUCHAR value) const;
  void ReadRegister(int bar_number, ULONG offset, PUSHORT value) const;
  void ReadRegister(int bar_number, ULONG offset, PULONG value) const;

  void WriteRegister(int bar_number, ULONG offset, UCHAR value) const;
  void WriteRegister(int bar_number, ULONG offset, USHORT value) const;
  void WriteRegister(int bar_number, ULONG offset, ULONG value) const;

  NDIS_HANDLE miniport_handle() const { return miniport_handle_; }

  NDIS_HANDLE net_buffer_list_pool() const { return buffer_list_pool_; }

  NDIS_HANDLE interrupt_handle() const { return interrupt_handle_; }

  NDIS_HANDLE dma_handle() const { return dma_handle_; }

  ULONG recommended_sg_list_size() const { return recommended_sg_list_size_; }

  IO_INTERRUPT_MESSAGE_INFO* msi_info_table() const { return msi_info_table_; }

  // Write value into kDoorbellRegister register.
  void WriteDoorbell(UINT32 doorbell_index, UINT32 value);

  // Release all registered handlers.
  void Release();

  // Completes all running interrupts and prevents new ones.
  void DeregisterInterrupts();

 private:
  // Help function to translate offset to mapped memory address.
  PULONG OffsetToAddress(int bar_number, ULONG offset) const {
    return (PULONG)((PUCHAR)bars_[bar_number].virtual_address + offset);
  }

  NDIS_STATUS AllocateNetBufferListPool();
  NDIS_STATUS RegisterDma();
  ULONG GetDmaRegistrationFlags();
  NDIS_STATUS RegisterInterrupt(PVOID adapter_context);

  NDIS_HANDLE driver_handle_;
  NDIS_HANDLE miniport_handle_;

  NDIS_HANDLE dma_handle_;
  NDIS_HANDLE interrupt_handle_;
  NDIS_HANDLE buffer_list_pool_;
  BaseAddressRegister bars_[kGvnicBarCount];

  // The length in bytes that the NDIS framework recommends is preallocated for
  // each scatter gather list.
  ULONG recommended_sg_list_size_;

  IO_INTERRUPT_MESSAGE_INFO* msi_info_table_;
};

inline void AdapterResources::ReadRegister(int bar_number, ULONG offset,
                                           PUCHAR value) const {
  NdisReadRegisterUchar(OffsetToAddress(bar_number, offset), value);
}

inline void AdapterResources::ReadRegister(int bar_number, ULONG offset,
                                           PUSHORT value) const {
  NdisReadRegisterUshort(OffsetToAddress(bar_number, offset), value);
}

inline void AdapterResources::ReadRegister(int bar_number, ULONG offset,
                                           PULONG value) const {
  NdisReadRegisterUlong(OffsetToAddress(bar_number, offset), value);
}

inline void AdapterResources::WriteRegister(int bar_number, ULONG offset,
                                            UCHAR value) const {
  NdisWriteRegisterUchar((PUCHAR)OffsetToAddress(bar_number, offset), value);
}

inline void AdapterResources::WriteRegister(int bar_number, ULONG offset,
                                            USHORT value) const {
  NdisWriteRegisterUshort((PUSHORT)OffsetToAddress(bar_number, offset), value);
}

inline void AdapterResources::WriteRegister(int bar_number, ULONG offset,
                                            ULONG value) const {
  NdisWriteRegisterUlong((PULONG)OffsetToAddress(bar_number, offset), value);
}
#endif  // ADAPTER_RESOURCE_H_
