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

void MaskInterrupt(UINT32 irq_doorbell_index, AdapterContext* context) {
  KeMemoryBarrier();  // Make sure all read/write is done before ring door bell.
  context->resources.WriteDoorbell(irq_doorbell_index, kInterruptRequestMask);
}

bool ProcessRxRings(ULONG max_nbls_to_indicate, ULONG message_id,
                    UINT32 num_rx_rings, AdapterContext* context) {
  PacketAssembler packet_assembler(
      max_nbls_to_indicate, context->resources.net_buffer_list_pool(),
      context->resources.miniport_handle(), context->device.rsc_ipv4_enabled(),
      &context->statistics);
  bool all_packets_processed = true;
  for (UINT i = 0; i < num_rx_rings && packet_assembler.CanAllocateNBL(); i++) {
    RxRing* rx_ring =
        context->device.notify_manager()->GetRxRing(message_id, i);
    if (!rx_ring->is_init()) {
      continue;
    }

    all_packets_processed =
        all_packets_processed && rx_ring->ProcessPendingPackets(
                                     /*is_dpc_level=*/true, &packet_assembler);
  }

  packet_assembler.ReportPackets(context->resources.miniport_handle());
  return all_packets_processed;
}

}  //  namespace

// Handler to disable interrupts for diagnostic and troubleshooting purposes.
VOID MiniportDisableInterruptEx(_In_ PVOID miniport_interrupt_context) {
  DEBUGP(GVNIC_VERBOSE, "---> MiniportDisableInterruptEx");
  UNREFERENCED_PARAMETER(miniport_interrupt_context);

  DEBUGP(GVNIC_ERROR,
         "[%s] ERROR: Line-based interrupts are not used by the gVNIC device, "
         "but the framework is attempting to disable them anyway which will "
         "have no effect.",
         __FUNCTION__);

  DEBUGP(GVNIC_VERBOSE, "<--- MiniportDisableInterruptEx\n");
}

// Handler to enable interrupts for diagnostic and troubleshooting purposes.
VOID MiniportEnableInterruptEx(_In_ PVOID miniport_interrupt_context) {
  DEBUGP(GVNIC_VERBOSE, "---> MiniportEnableInterruptEx");
  UNREFERENCED_PARAMETER(miniport_interrupt_context);

  DEBUGP(GVNIC_ERROR,
         "[%s] ERROR: Line-based interrupts are not used by the gVNIC device, "
         "but the framework is attempting to enable them anyway which will "
         "have no effect.",
         __FUNCTION__);

  DEBUGP(GVNIC_VERBOSE, "<--- MiniportEnableInterruptEx");
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
  DEBUGP(GVNIC_VERBOSE, "---> MiniportEnableMSIInterrupt");

  AdapterContext* context =
      static_cast<AdapterContext*>(miniport_interrupt_context);
  const NotifyManager* notify_manager = context->device.notify_manager();
  if (message_id == notify_manager->manager_queue_message_id()) {
    DEBUGP(GVNIC_ERROR,
           "[%s] ERROR: Message ID %d is a management interrupt which cannot "
           "be selectively enabled.",
           __FUNCTION__, message_id);
  } else {
    DEBUGP(GVNIC_WARNING,
           "[%s] WARNING: Enabling interrupts for message ID %d after "
           "disabling for diagnostic purposes.",
           __FUNCTION__, message_id);
    const UINT32 doorbell_index =
        notify_manager->GetInterruptDoorbellIndex(message_id);
    AckInterrupt(doorbell_index, context);
  }

  DEBUGP(GVNIC_VERBOSE, "<--- MiniportEnableMSIInterrupt");
}

// Handler to disable a message interrupt for diagnostic and troubleshooting.
VOID MiniportDisableMSIInterrupt(_In_ PVOID miniport_interrupt_context,
                                 _In_ ULONG message_id) {
  DEBUGP(GVNIC_VERBOSE, "---> MiniportDisableMSIInterrupt");

  AdapterContext* context =
      static_cast<AdapterContext*>(miniport_interrupt_context);
  const NotifyManager* notify_manager = context->device.notify_manager();
  if (message_id == notify_manager->manager_queue_message_id()) {
    DEBUGP(GVNIC_ERROR,
           "[%s] ERROR: Message ID %d is a management interrupt which cannot "
           "be selectively disabled.",
           __FUNCTION__, message_id);
  } else {
    DEBUGP(GVNIC_WARNING,
           "[%s] WARNING: Disabling interrupts for message ID %d for "
           "diagnostic purposes.",
           __FUNCTION__, message_id);
    const UINT32 doorbell_index =
        notify_manager->GetInterruptDoorbellIndex(message_id);
    MaskInterrupt(doorbell_index, context);
  }

  DEBUGP(GVNIC_VERBOSE, "<--- MiniportDisableMSIInterrupt");
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

  if (message_id == notify_manager->manager_queue_message_id()) {
    context->device.HandleManagementQueueRequest();
  } else {
    if (!context->device.QueueInterruptsEnabled()) {
      // This DPC was scheduled before we masked off all interrupts and began
      // tearing down the queues. The rings are no longer in a valid state.
      return;
    }

    const UINT32 doorbell_index =
        notify_manager->GetInterruptDoorbellIndex(message_id);
    MaskInterrupt(doorbell_index, context);

    bool ack_interrupt = true;
    TxRing* tx_ring = notify_manager->GetTxRing(message_id);
    UINT32 num_rx_rings = notify_manager->GetRxRingCount(message_id);

    // This is tx/rx interrupt.
    NT_ASSERT(tx_ring != nullptr || num_rx_rings > 0);

    if (tx_ring != nullptr && tx_ring->is_init()) {
      tx_ring->ProcessCompletePackets();
    }

    if (num_rx_rings > 0) {
      auto* rx_throttle_parameters =
        static_cast<NDIS_RECEIVE_THROTTLE_PARAMETERS*>(
          receive_throttle_parameters);

      bool all_packets_processed =
          ProcessRxRings(rx_throttle_parameters->MaxNblsToIndicate, message_id,
                         num_rx_rings, context);

      if (!all_packets_processed) {
        ack_interrupt = false;
        rx_throttle_parameters->MoreNblsPending = true;
      }
    }

    if (ack_interrupt) {
      AckInterrupt(doorbell_index, context);

      // See if the NIC has processed any tx or rx packets while device
      // interrupts were masked off.
      if (tx_ring != nullptr && tx_ring->is_init()) {
        tx_ring->ProcessCompletePackets();
      }
      if (num_rx_rings > 0) {
        ProcessRxRings(NDIS_INDICATE_ALL_NBLS, message_id, num_rx_rings,
                       context);
      }
    }
  }

  DEBUGP(GVNIC_VERBOSE, "<--- MiniportMSIInterruptDPC");
}
