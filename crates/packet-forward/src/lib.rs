//! Rust implementation of the IBC packet forwarding middleware,
//! using [`ibc_middleware_core`].

#![cfg_attr(not(test), no_std)]

extern crate alloc;

mod msg;

use alloc::format;
use core::fmt;

use ibc_app_transfer::context::{TokenTransferExecutionContext, TokenTransferValidationContext};
use ibc_app_transfer::handler::{send_transfer_execute, send_transfer_validate};
use ibc_app_transfer_types::packet::PacketData;
use ibc_core_channel::context::{SendPacketExecutionContext, SendPacketValidationContext};
use ibc_core_channel_types::acknowledgement::{
    Acknowledgement, AcknowledgementStatus, StatusValue as AckStatusValue,
};
use ibc_core_channel_types::channel::{Counterparty, Order};
use ibc_core_channel_types::error::{ChannelError, PacketError};
use ibc_core_channel_types::packet::Packet;
use ibc_core_channel_types::Version;
use ibc_core_host_types::identifiers::{ChannelId, ConnectionId, PortId};
use ibc_core_router::module::Module as IbcCoreModule;
use ibc_core_router_types::module::ModuleExtras;
use ibc_primitives::prelude::*;
use ibc_primitives::Signer;

enum MiddlewareError {
    /// Error message with module extras.
    MessageWithExtras(ModuleExtras, String),
    /// Error message.
    Message(String),
    /// Forward the call to the next middleware.
    Forward,
}

/// Module name of the PFM.
const MODULE: &str = "packet-forward-middleware";

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

    /// Error returned by fallible operations.
    type Error: fmt::Display;

    /// Return a [`SendPacketExecutionContext`] impl.
    fn send_packet_execution_ctx(&mut self) -> &mut Self::SendPacketExecutionContext;

    /// Return a [`SendPacketValidationContext`] impl.
    fn send_packet_validation_ctx(&self) -> &Self::SendPacketValidationContext;

    /// Return a [`TokenTransferExecutionContext`] impl.
    fn token_transfer_execution_ctx(&mut self) -> &mut Self::TokenTransferExecutionContext;

    /// Return a [`TokenTransferValidationContext`] impl.
    fn token_transfer_validation_ctx(&self) -> &Self::TokenTransferValidationContext;

    /// Given some arbitrary data blob, return an address native
    /// to the source chain.
    fn encode_blob_as_address(&self, data: &[u8]) -> Result<Signer, Self::Error>;

    /// Whether ICS-20 packet refunding is disabled.
    fn non_refundable(&self) -> bool;

    /// Whether denom composition is disabled.
    fn disable_denom_composition(&self) -> bool;
}

/// [Packet forward middleware](https://github.com/cosmos/ibc-apps/blob/26f3ad8/middleware/packet-forward-middleware/README.md)
/// entrypoint, which intercepts compatible ICS-20 packets and forwards them to other chains.
#[derive(Debug)]
pub struct PacketForwardMiddleware<M> {
    next: M,
}

impl<M> PacketForwardMiddleware<M>
where
    M: IbcCoreModule + PfmContext,
{
    fn receive_funds(
        &mut self,
        source_packet: &Packet,
        source_transfer_pkt: PacketData,
        override_receiver: Signer,
        signer: &Signer,
    ) -> Result<(), MiddlewareError> {
        let override_packet = {
            let ics20_packet_data = PacketData {
                receiver: override_receiver,
                memo: String::new().into(),
                ..source_transfer_pkt
            };

            let encoded_packet_data = serde_json::to_vec(&ics20_packet_data).map_err(|err| {
                MiddlewareError::Message(format!("failed to encode ICS-20 packet: {err}"))
            })?;

            Packet {
                data: encoded_packet_data,
                ..source_packet.clone()
            }
        };

        let (extras, maybe_ack) = self.next.on_recv_packet_execute(&override_packet, signer);

        let Some(ack) = maybe_ack else {
            return Err(MiddlewareError::MessageWithExtras(
                extras,
                "ack is nil".to_owned(),
            ));
        };

        let ack: AcknowledgementStatus = serde_json::from_slice(ack.as_bytes())
            .map_err(|err| MiddlewareError::Message(format!("failed to parse ack: {err}")))?;

        if !ack.is_successful() {
            return Err(MiddlewareError::Message(format!("ack error: {ack}")));
        }

        Ok(())
    }

    fn on_recv_packet_execute_inner(
        &mut self,
        packet: &Packet,
        relayer: &Signer,
    ) -> Result<ModuleExtras, MiddlewareError> {
        let (transfer_pkt, metadata) = decode_forward_msg(packet)?;

        // TODO: these values should be loaded from storage
        let processed = false;
        let disable_denom_composition = true;

        // NB: this is supposed to be set by other middlewares,
        // but current we have no way of writing to a namespace
        // shared between all middlewares... unless we impl some
        // form of message passing (from the current to the next
        // middleware, as arguments to the event reactor fns)
        //
        // let non_refundable = false;

        // override the receiver so that senders cannot move funds through arbitrary addresses
        let override_receiver = get_receiver(&self.next, &metadata.channel, &metadata.receiver)?;

        todo!()
    }
}

impl<M> IbcCoreModule for PacketForwardMiddleware<M>
where
    M: IbcCoreModule + PfmContext,
{
    fn on_recv_packet_execute(
        &mut self,
        packet: &Packet,
        relayer: &Signer,
    ) -> (ModuleExtras, Option<Acknowledgement>) {
        self.on_recv_packet_execute_inner(packet, relayer)
            .map_or_else(
                |middleware_err| match middleware_err {
                    MiddlewareError::Forward => self.next.on_recv_packet_execute(packet, relayer),
                    MiddlewareError::Message(err) => {
                        (ModuleExtras::empty(), Some(new_error_ack(err).into()))
                    }
                    MiddlewareError::MessageWithExtras(extras, err) => {
                        (extras, Some(new_error_ack(err).into()))
                    }
                },
                |extras| (extras, None),
            )
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

#[inline]
fn new_error_ack(message: impl fmt::Display) -> AcknowledgementStatus {
    AcknowledgementStatus::error(
        AckStatusValue::new(format!("{MODULE} error: {message}"))
            .expect("Acknowledgement error must not be empty"),
    )
}

fn receiver_pre_img(channel: &ChannelId, original_sender: &str) -> Vec<u8> {
    format!("{channel}/{original_sender}").into_bytes()
}

fn get_receiver<C: PfmContext>(
    ctx: &C,
    channel: &ChannelId,
    original_sender: &str,
) -> Result<Signer, MiddlewareError> {
    let preimg = receiver_pre_img(channel, original_sender);
    ctx.encode_blob_as_address(&preimg)
        .map_err(|err| MiddlewareError::Message(err.to_string()))
}

fn decode_forward_msg(
    packet: &Packet,
) -> Result<(PacketData, msg::ForwardMetadata), MiddlewareError> {
    let Ok(transfer_pkt) = serde_json::from_slice::<PacketData>(&packet.data) else {
        // NB: if `packet.data` is not a valid fungible token transfer
        // packet, we forward the call to the next middleware
        return Err(MiddlewareError::Forward);
    };

    let Ok(json_obj_memo) = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(
        transfer_pkt.memo.as_ref(),
    ) else {
        // NB: if the ICS-20 packet memo is not a valid JSON object, we forward
        // this call to the next middleware
        return Err(MiddlewareError::Forward);
    };

    if !json_obj_memo.contains_key("forward") {
        // NB: the memo was a valid json object, but it wasn't up to
        // the PFM to consume it, so we forward the call to the next middleware
        return Err(MiddlewareError::Forward);
    }

    serde_json::from_value(json_obj_memo.into()).map_or_else(
        |err| Err(MiddlewareError::Message(err.to_string())),
        |msg::PacketMetadata { forward }| Ok((transfer_pkt, forward)),
    )
}

#[allow(dead_code)]
fn join_module_extras(mut first: ModuleExtras, mut second: ModuleExtras) -> ModuleExtras {
    first.events.append(&mut second.events);
    first.log.append(&mut second.log);
    first
}
