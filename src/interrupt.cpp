// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "interrupt.h"  // NOLINT: include directory

#include <ndis.h>

#include "abi.h"               // NOLINT: include directory
#include "adapter.h"           // NOLINT: include directory
#include "adapter_resource.h"  // NOLINT: include directory
#include "notify_manager.h"    // NOLINT: include directory
#include "packet_assembler.h"  // NOLINT: include directory
#include "rx_ring.h"           // NOLINT: include directory
#include "trace.h"             // NOLINT: include directory
#include "tx_ring.h"           // NOLINT: include directory
#include "utils.h"             // NOLINT: include directory

#include "interrupt.tmh"  // NOLINT: trace message header

namespace {
constexpr UINT32 kInterruptAckEvent =
    kInterruptRequestACK | kInterruptRequestEvent;

void AckInterrupt(UINT32 irq_doorbell_index, AdapterContext* context) {
  KeMemoryBarrier();  // Make sure all read/write is done before ring door bell.
  context->resources.WriteDoorbell(irq_doorbell_index, kInterruptAckEvent);
}
}  //  namespace

// Handler to disable interrupts for diagnostic and troubleshooting purposes.
VOID MiniportDisableInterruptEx(_In_ PVOID miniport_interrupt_context) {
  DEBUGP(GVNIC_VERBOSE, "---> MiniportDisableInterruptEx\n");
  UNREFERENCED_PARAMETER(miniport_interrupt_context);

  // TODO(ningyang): Disable interrupts on all queues

  DEBUGP(GVNIC_VERBOSE, "<--- MiniportDisableInterruptEx\n");
}

// Handler to enable interrupts for diagnostic and troubleshooting purposes.
VOID MiniportEnableInterruptEx(_In_ PVOID miniport_interrupt_context) {
  DEBUGP(GVNIC_VERBOSE, "---> MiniportEnableInterruptEx\n");
  UNREFERENCED_PARAMETER(miniport_interrupt_context);

  // TODO(ningyang): Enable interrupts on all queues

  DEBUGP(GVNIC_VERBOSE, "<--- MiniportEnableInterruptEx\n");
}

// Handler for interrupt.
BOOLEAN MiniportInterrupt(_In_ PVOID miniport_interrupt_context,
                          _Out_ PBOOLEAN queue_default_interrupt_dpc,
                          _Out_ PULONG target_processors) {
  DEBUGP(GVNIC_VERBOSE, "---> MiniportInterrupt\n");
  UNREFERENCED_PARAMETER(miniport_interrupt_context);

  *target_processors = 0;
  *queue_default_interrupt_dpc = FALSE;

  DEBUGP(GVNIC_VERBOSE, "<--- MiniportInterrupt\n");
  return FALSE;
}

// Handler to complete the deferred processing of an interrupt.
VOID MiniportInterruptDPC(_In_ NDIS_HANDLE miniport_interrupt_context,
                          _In_ PVOID miniport_dpc_context,
                          _In_ PVOID receive_throttle_parameters,
                          _In_ PVOID ndis_reserved) {
  UNREFERENCED_PARAMETER(miniport_interrupt_context);
  UNREFERENCED_PARAMETER(miniport_dpc_context);
  UNREFERENCED_PARAMETER(receive_throttle_parameters);
  UNREFERENCED_PARAMETER(ndis_reserved);
}

// Handler for to enable a message interrupt for diagnostic and troubleshooting.
VOID MiniportEnableMSIInterrupt(_In_ PVOID miniport_interrupt_context,
                                _In_ ULONG message_id) {
  DEBUGP(GVNIC_VERBOSE, "---> MiniportEnableMSIInterrupt\n");
  UNREFERENCED_PARAMETER(miniport_interrupt_context);
  UNREFERENCED_PARAMETER(message_id);

  DEBUGP(GVNIC_VERBOSE, "<--- MiniportEnableMSIInterrupt\n");
}

// Handler to disable a message interrupt for diagnostic and troubleshooting.
VOID MiniportDisableMSIInterrupt(_In_ PVOID miniport_interrupt_context,
                                 _In_ ULONG message_id) {
  DEBUGP(GVNIC_VERBOSE, "---> MiniportDisableMSIInterrupt\n");
  UNREFERENCED_PARAMETER(miniport_interrupt_context);
  UNREFERENCED_PARAMETER(message_id);

  DEBUGP(GVNIC_VERBOSE, "<--- MiniportDisableMSIInterrupt\n");
}

// Handler for a message-based interrupt.
BOOLEAN MiniportMSIInterrupt(_In_ PVOID miniport_interrupt_context,
                             _In_ ULONG message_id,
                             _Out_ PBOOLEAN queue_default_interrupt_dpc,
                             _Out_ PULONG target_processors) {
  UNREFERENCED_PARAMETER(miniport_interrupt_context);
  UNREFERENCED_PARAMETER(message_id);
  UNREFERENCED_PARAMETER(target_processors);

  DEBUGP(GVNIC_VERBOSE, "---> MiniportMSIInterrupt with id %u", message_id);

  // MSI has been configured to send interrupt to the correct processor.
  // Just schedule the DPC on the current processor.
  *queue_default_interrupt_dpc = TRUE;
  DEBUGP(GVNIC_VERBOSE, "<--- MiniportMSIInterrupt");
  return TRUE;
}

// Handler to complete the deferred processing of a message-based interrupt.
VOID MiniportMSIInterruptDpc(_In_ PVOID miniport_interrupt_context,
                             _In_ ULONG message_id,
                             _In_ PVOID miniport_dpc_context,
#if NDIS_SUPPORT_NDIS620
                             _In_ PVOID receive_throttle_parameters,
                             _In_ PVOID ndis_reserved_2) {
#else
                             _In_ PULONG ndis_reserved_1,
                             _In_ PULONG ndis_reserved_2) {
#endif
  UNREFERENCED_PARAMETER(miniport_dpc_context);
  UNREFERENCED_PARAMETER(ndis_reserved_2);
  DEBUGP(GVNIC_VERBOSE, "---> MiniportMSIInterruptDPC with id %u", message_id);
  AdapterContext* context =
      static_cast<AdapterContext*>(miniport_interrupt_context);
  const NotifyManager* notify_manager = context->device.notify_manager();

  bool ack_interrupt = true;
  if (message_id == notify_manager->manager_queue_message_id()) {
    context->device.HandleManagementQueueRequest();
  } else {
    TxRing* tx_ring = notify_manager->GetTxRing(message_id);
    UINT32 num_rx_rings = notify_manager->GetRxRingCount(message_id);

    // This is tx/rx interrupt.
    NT_ASSERT(tx_ring != nullptr || num_rx_rings > 0);

    if (tx_ring != nullptr) {
      NT_ASSERT(GetCurrentProcessorIndex() == tx_ring->slice());
      tx_ring->ProcessCompletePackets();
    }

    if (num_rx_rings > 0) {
#if NDIS_SUPPORT_NDIS620
      auto* rx_throttle_parameters =
        static_cast<NDIS_RECEIVE_THROTTLE_PARAMETERS*>(
          receive_throttle_parameters);
      PacketAssembler packet_assembler(
          rx_throttle_parameters->MaxNblsToIndicate,
          context->resources.net_buffer_list_pool(),
          context->resources.miniport_handle(),
          context->device.rsc_ipv4_enabled(), &context->statistics);
      bool all_packet_processed = true;

      for (UINT i = 0; i < num_rx_rings && packet_assembler.CanAllocateNBL();
           i++) {
        RxRing* rx_ring = notify_manager->GetRxRing(message_id, i);
        all_packet_processed = all_packet_processed &&
                               rx_ring->ProcessPendingPackets(
                                   /*is_dpc_level=*/true, &packet_assembler);
      }

      if (!all_packet_processed) {
        ack_interrupt = false;
        rx_throttle_parameters->MoreNblsPending = true;
      }
#else
      UNREFERENCED_PARAMETER(ndis_reserved_1);
      PacketAssembler packet_assembler(kIndicateAllNBLs);
      for (UINT i = 0; i < num_rx_rings && packet_assembler.CanAllocateNBL();
           i++) {
        RxRing* rx_ring = notify_manager->GetRxRing(message_id, i);
        rx_ring->ProcessPendingPackets(/*is_dpc_level=*/true,
                                       &packet_assembler);
      }
#endif
      packet_assembler.ReportPackets(context->resources.miniport_handle());
    }
  }

  if (ack_interrupt) {
    AckInterrupt(notify_manager->GetInterruptDoorbellIndex(message_id),
                 context);
  }

  DEBUGP(GVNIC_VERBOSE, "<--- MiniportMSIInterruptDPC");
}
