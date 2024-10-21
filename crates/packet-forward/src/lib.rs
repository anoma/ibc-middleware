//! Rust implementation of the IBC packet forwarding middleware,
//! using [`ibc_middleware_core`].

#![cfg_attr(not(test), no_std)]

extern crate alloc;

mod msg;

use ibc_app_transfer::context::{TokenTransferExecutionContext, TokenTransferValidationContext};
use ibc_app_transfer::handler::{send_transfer_execute, send_transfer_validate};
use ibc_app_transfer_types::packet::PacketData;
use ibc_core_channel::context::{SendPacketExecutionContext, SendPacketValidationContext};
use ibc_core_channel_types::acknowledgement::Acknowledgement;
use ibc_core_channel_types::channel::{Counterparty, Order};
use ibc_core_channel_types::error::{ChannelError, PacketError};
use ibc_core_channel_types::packet::Packet;
use ibc_core_channel_types::Version;
use ibc_core_host_types::identifiers::{ChannelId, ConnectionId, PortId};
use ibc_core_router::module::Module as IbcCoreModule;
use ibc_core_router_types::module::ModuleExtras;
use ibc_middleware_core::ics26_callbacks::Module;
use ibc_middleware_core::store::Store;
use ibc_primitives::prelude::*;
use ibc_primitives::Signer;

/// The storage namespace of the PFM.
const STORE_NAMESPACE: &str = "packet-forward-middleware";

/// Context data required by the [`PacketForwardMiddleware`].
pub trait PfmContext {
    /// Context required by [`send_transfer_execute`].
    type SendPacketExecutionContext: SendPacketExecutionContext;

    /// Context required by [`send_transfer_validate`].
    type SendPacketValidationContext: SendPacketValidationContext;

    /// Context required by [`send_transfer_execute`].
    type TokenTransferExecutionContext: TokenTransferExecutionContext;

    /// Context required by [`send_transfer_validate`].
    type TokenTransferValidationContext: TokenTransferValidationContext;

    /// Return a [`SendPacketExecutionContext`] impl.
    fn send_packet_execution_ctx(&mut self) -> &mut Self::SendPacketExecutionContext;

    /// Return a [`SendPacketValidationContext`] impl.
    fn send_packet_validation_ctx(&self) -> &Self::SendPacketValidationContext;

    /// Return a [`TokenTransferExecutionContext`] impl.
    fn token_transfer_execution_ctx(&mut self) -> &mut Self::TokenTransferExecutionContext;

    /// Return a [`TokenTransferValidationContext`] impl.
    fn token_transfer_validation_ctx(&self) -> &Self::TokenTransferValidationContext;
}

/// [Packet forward middleware](https://github.com/cosmos/ibc-apps/blob/26f3ad8/middleware/packet-forward-middleware/README.md)
/// entrypoint, which intercepts compatible ICS-20 packets and forwards them to other chains.
#[derive(Debug)]
pub struct PacketForwardMiddleware<M> {
    next: M,
}

impl<M> Module for PacketForwardMiddleware<M>
where
    M: Module + PfmContext,
{
    fn store(&self) -> &dyn Store {
        self.next.store()
    }

    fn store_mut(&mut self) -> &mut dyn Store {
        self.next.store_mut()
    }

    fn upcast_to_core(&self) -> &dyn IbcCoreModule {
        self
    }

    fn upcast_to_core_mut(&mut self) -> &mut dyn IbcCoreModule {
        self
    }
}

impl<M> IbcCoreModule for PacketForwardMiddleware<M>
where
    M: Module + PfmContext,
{
    fn on_recv_packet_execute(
        &mut self,
        packet: &Packet,
        relayer: &Signer,
    ) -> (ModuleExtras, Acknowledgement) {
        let Ok(_data) = serde_json::from_slice::<PacketData>(&packet.data) else {
            // NB: if `packet.data` is not a valid fungible token transfer
            // packet, we forward the call to the next middleware
            return self.next.on_recv_packet_execute(packet, relayer);
        };

        self.next.on_recv_packet_execute(packet, relayer)
    }

    fn on_acknowledgement_packet_validate(
        &self,
        packet: &Packet,
        acknowledgement: &Acknowledgement,
        relayer: &Signer,
    ) -> Result<(), PacketError> {
        self.next
            .on_acknowledgement_packet_validate(packet, acknowledgement, relayer)
    }

    fn on_acknowledgement_packet_execute(
        &mut self,
        packet: &Packet,
        acknowledgement: &Acknowledgement,
        relayer: &Signer,
    ) -> (ModuleExtras, Result<(), PacketError>) {
        self.next
            .on_acknowledgement_packet_execute(packet, acknowledgement, relayer)
    }

    fn on_timeout_packet_validate(
        &self,
        packet: &Packet,
        relayer: &Signer,
    ) -> Result<(), PacketError> {
        self.next.on_timeout_packet_validate(packet, relayer)
    }

    fn on_timeout_packet_execute(
        &mut self,
        packet: &Packet,
        relayer: &Signer,
    ) -> (ModuleExtras, Result<(), PacketError>) {
        self.next.on_timeout_packet_execute(packet, relayer)
    }

    // =========================================================================
    // the calls below are simply forwarded to the next middleware
    // =========================================================================

    fn on_chan_open_init_validate(
        &self,
        order: Order,
        connection_hops: &[ConnectionId],
        port_id: &PortId,
        channel_id: &ChannelId,
        counterparty: &Counterparty,
        version: &Version,
    ) -> Result<Version, ChannelError> {
        self.next.on_chan_open_init_validate(
            order,
            connection_hops,
            port_id,
            channel_id,
            counterparty,
            version,
        )
    }

    fn on_chan_open_init_execute(
        &mut self,
        order: Order,
        connection_hops: &[ConnectionId],
        port_id: &PortId,
        channel_id: &ChannelId,
        counterparty: &Counterparty,
        version: &Version,
    ) -> Result<(ModuleExtras, Version), ChannelError> {
        self.next.on_chan_open_init_execute(
            order,
            connection_hops,
            port_id,
            channel_id,
            counterparty,
            version,
        )
    }

    fn on_chan_open_try_validate(
        &self,
        order: Order,
        connection_hops: &[ConnectionId],
        port_id: &PortId,
        channel_id: &ChannelId,
        counterparty: &Counterparty,
        counterparty_version: &Version,
    ) -> Result<Version, ChannelError> {
        self.next.on_chan_open_try_validate(
            order,
            connection_hops,
            port_id,
            channel_id,
            counterparty,
            counterparty_version,
        )
    }

    fn on_chan_open_try_execute(
        &mut self,
        order: Order,
        connection_hops: &[ConnectionId],
        port_id: &PortId,
        channel_id: &ChannelId,
        counterparty: &Counterparty,
        counterparty_version: &Version,
    ) -> Result<(ModuleExtras, Version), ChannelError> {
        self.next.on_chan_open_try_execute(
            order,
            connection_hops,
            port_id,
            channel_id,
            counterparty,
            counterparty_version,
        )
    }

    fn on_chan_open_ack_validate(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
        counterparty_version: &Version,
    ) -> Result<(), ChannelError> {
        self.next
            .on_chan_open_ack_validate(port_id, channel_id, counterparty_version)
    }

    fn on_chan_open_ack_execute(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
        counterparty_version: &Version,
    ) -> Result<ModuleExtras, ChannelError> {
        self.next
            .on_chan_open_ack_execute(port_id, channel_id, counterparty_version)
    }

    fn on_chan_open_confirm_validate(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<(), ChannelError> {
        self.next.on_chan_open_confirm_validate(port_id, channel_id)
    }

    fn on_chan_open_confirm_execute(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<ModuleExtras, ChannelError> {
        self.next.on_chan_open_confirm_execute(port_id, channel_id)
    }

    fn on_chan_close_init_validate(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<(), ChannelError> {
        self.next.on_chan_close_init_validate(port_id, channel_id)
    }

    fn on_chan_close_init_execute(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<ModuleExtras, ChannelError> {
        self.next.on_chan_close_init_execute(port_id, channel_id)
    }

    fn on_chan_close_confirm_validate(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<(), ChannelError> {
        self.next
            .on_chan_close_confirm_validate(port_id, channel_id)
    }

    fn on_chan_close_confirm_execute(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<ModuleExtras, ChannelError> {
        self.next.on_chan_close_confirm_execute(port_id, channel_id)
    }
}
