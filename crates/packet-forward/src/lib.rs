//! Rust implementation of the IBC packet forwarding middleware.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

mod msg;
mod state;

use alloc::format;
use core::fmt;
use core::num::NonZeroU8;

use ibc_app_transfer_types::msgs::transfer::MsgTransfer;
use ibc_app_transfer_types::packet::PacketData;
use ibc_app_transfer_types::{Coin, PrefixedDenom, TracePrefix};
use ibc_core_channel_types::acknowledgement::{
    Acknowledgement, AcknowledgementStatus, StatusValue as AckStatusValue,
};
use ibc_core_channel_types::channel::{Counterparty, Order};
use ibc_core_channel_types::error::{ChannelError, PacketError};
use ibc_core_channel_types::packet::Packet;
use ibc_core_channel_types::timeout::{TimeoutHeight, TimeoutTimestamp};
use ibc_core_channel_types::Version;
use ibc_core_host_types::identifiers::{ChannelId, ConnectionId, PortId};
use ibc_core_router::module::Module as IbcCoreModule;
use ibc_core_router_types::event::{ModuleEvent, ModuleEventAttribute};
use ibc_core_router_types::module::ModuleExtras;
use ibc_primitives::prelude::*;
use ibc_primitives::Signer;

#[doc(inline)]
pub use self::msg::Duration;
#[doc(inline)]
pub use self::state::InFlightPacket;

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

/// Default packet forward timeout duration.
const DEFAULT_FORWARD_TIMEOUT: dur::Duration = {
    const DURATION_IN_SECS: u128 = 5 * 60;
    dur::Duration::from_secs(DURATION_IN_SECS)
};

/// Default packet forward retries on failure.
const DEFAULT_FORWARD_RETRIES: NonZeroU8 = unsafe { NonZeroU8::new_unchecked(1) };

/// Context data required by the [`PacketForwardMiddleware`].
pub trait PfmContext {
    /// Error returned by fallible operations.
    type Error: fmt::Display;

    /// Execute an ICS-20 transfer.
    fn send_transfer_execute(&mut self, msg: MsgTransfer) -> Result<(), Self::Error>;

    /// Get an escrow account that will receive funds to be forwarded through
    /// channel `channel`.
    ///
    /// The account should not be controllable by `original_sender`, but the
    /// Packet Forward Middleware should be able to freely deposit and withdraw
    /// funds from it.
    fn override_receiver(
        &self,
        channel: &ChannelId,
        original_sender: &Signer,
    ) -> Result<Signer, Self::Error>;

    /// Given a timeout duration, return a [`TimeoutTimestamp`], to be
    /// applied to some hop.
    fn timeout_timestamp(
        &self,
        timeout_duration: dur::Duration,
    ) -> Result<TimeoutTimestamp, Self::Error>;

    /// Stores an [in-flight packet](InFlightPacket) (i.e. a packet
    /// that is currently being transmitted over multiple hops by the PFM).
    fn store_inflight_packet(&mut self, inflight_packet: InFlightPacket)
        -> Result<(), Self::Error>;
}

/// [Packet forward middleware](https://github.com/cosmos/ibc-apps/blob/26f3ad8/middleware/packet-forward-middleware/README.md)
/// entrypoint, which intercepts compatible ICS-20 packets and forwards them to other chains.
#[derive(Debug)]
pub struct PacketForwardMiddleware<M> {
    next: M,
}

impl<M> PacketForwardMiddleware<M> {
    /// Wrap an existing middleware in the PFM.
    pub const fn next(next: M) -> Self {
        Self { next }
    }
}

impl<M> PacketForwardMiddleware<M>
where
    M: IbcCoreModule + PfmContext,
{
    fn get_denom_for_this_chain(
        &self,
        source_packet: &Packet,
        source_coin: &Coin<PrefixedDenom>,
    ) -> Result<Coin<PrefixedDenom>, MiddlewareError> {
        let mut coin = source_coin.clone();

        // NB: Suppose the following packet flow `A => B => C`,
        // on chains A, B, and C. If we are the first hop (i.e. B),
        // then we must unwrap the denom.
        coin.denom.trace_path.remove_prefix(&TracePrefix::new(
            source_packet.port_id_on_b.clone(),
            source_packet.chan_id_on_b.clone(),
        ));

        Ok(coin)
    }

    fn forward_transfer_packet(
        &mut self,
        inflight_packet: Option<InFlightPacket>,
        src_packet: &Packet,
        fwd_metadata: msg::ForwardMetadata,
        original_sender: Signer,
        override_receiver: Signer,
        token_and_amount: Coin<PrefixedDenom>,
    ) -> Result<ModuleExtras, MiddlewareError> {
        let mut attributes = {
            let mut attributes = Vec::with_capacity(8);

            // NB: initial set of attrs
            push_event_attr(
                &mut attributes,
                "escrow-amount".to_owned(),
                token_and_amount.to_string(),
            );
            push_event_attr(
                &mut attributes,
                "escrow-account".to_owned(),
                override_receiver.to_string(),
            );
            push_event_attr(
                &mut attributes,
                "sender".to_owned(),
                original_sender.to_string(),
            );
            push_event_attr(
                &mut attributes,
                "receiver".to_owned(),
                fwd_metadata.receiver.to_string(),
            );
            push_event_attr(
                &mut attributes,
                "port".to_owned(),
                fwd_metadata.port.to_string(),
            );
            push_event_attr(
                &mut attributes,
                "channel".to_owned(),
                fwd_metadata.channel.to_string(),
            );

            attributes
        };

        let timeout = fwd_metadata
            .timeout
            .map_or(DEFAULT_FORWARD_TIMEOUT, |msg::Duration(d)| d);
        let retries = fwd_metadata.retries.unwrap_or(DEFAULT_FORWARD_RETRIES);

        let next_memo = fwd_metadata
            .next
            .as_ref()
            .map(|next| {
                serde_json::to_string(next).map_err(|err| {
                    MiddlewareError::Message(format!("Failed to encode next memo: {err}"))
                })
            })
            .transpose()?
            .unwrap_or_default()
            .into();

        let fwd_msg_transfer = MsgTransfer {
            port_id_on_a: fwd_metadata.port,
            chan_id_on_a: fwd_metadata.channel,
            timeout_height_on_b: TimeoutHeight::Never,
            timeout_timestamp_on_b: self.next.timeout_timestamp(timeout).map_err(|err| {
                MiddlewareError::Message(format!(
                    "Failed to get timeout timestamp for fwd msg transfer: {err}"
                ))
            })?,
            packet_data: PacketData {
                sender: override_receiver,
                receiver: fwd_metadata.receiver,
                token: token_and_amount,
                memo: next_memo,
            },
        };

        self.next
            .send_transfer_execute(fwd_msg_transfer)
            .map_err(|err| {
                MiddlewareError::Message(format!("Failed to send forward packet: {err}"))
            })?;

        self.next
            .store_inflight_packet(retrieve_inflight_packet(
                inflight_packet,
                original_sender,
                src_packet,
                retries,
                timeout,
            ))
            .map_err(|err| {
                MiddlewareError::Message(format!("Failed to store in-flight packet: {err}"))
            })?;

        push_event_attr(
            &mut attributes,
            "info".to_owned(),
            "Packet has been successfully forwarded".to_owned(),
        );

        Ok({
            let mut extras = ModuleExtras::empty();
            emit_event_with_attrs(&mut extras, attributes);
            extras
        })
    }

    fn receive_funds(
        &mut self,
        source_packet: &Packet,
        source_transfer_pkt: PacketData,
        override_receiver: Signer,
        relayer: &Signer,
    ) -> Result<ModuleExtras, MiddlewareError> {
        let override_packet = {
            let ics20_packet_data = PacketData {
                receiver: override_receiver,
                memo: String::new().into(),
                ..source_transfer_pkt
            };

            let encoded_packet_data = serde_json::to_vec(&ics20_packet_data).map_err(|err| {
                MiddlewareError::Message(format!("Failed to encode ICS-20 packet: {err}"))
            })?;

            Packet {
                data: encoded_packet_data,
                ..source_packet.clone()
            }
        };

        let (extras, maybe_ack) = self.next.on_recv_packet_execute(&override_packet, relayer);

        let Some(ack) = maybe_ack else {
            return Err(MiddlewareError::MessageWithExtras(
                extras,
                "Ack is nil".to_owned(),
            ));
        };

        match serde_json::from_slice::<AcknowledgementStatus>(ack.as_bytes()) {
            Ok(ack) if !ack.is_successful() => Err(MiddlewareError::MessageWithExtras(
                extras,
                format!("Ack error: {ack}"),
            )),
            Ok(_) => Ok(extras),
            Err(err) => Err(MiddlewareError::MessageWithExtras(
                extras,
                format!("Failed to parse ack: {err}"),
            )),
        }
    }

    fn on_recv_packet_execute_inner(
        &mut self,
        packet: &Packet,
        relayer: &Signer,
    ) -> Result<ModuleExtras, MiddlewareError> {
        let (transfer_pkt, fwd_metadata) = decode_forward_msg(packet)?;

        let override_receiver =
            get_receiver(&self.next, &fwd_metadata.channel, &transfer_pkt.sender)?;
        let target_coin = self.get_denom_for_this_chain(packet, &transfer_pkt.token)?;
        let original_sender = transfer_pkt.sender.clone();

        let receive_funds_extras =
            self.receive_funds(packet, transfer_pkt, override_receiver.clone(), relayer)?;
        let forward_transfer_packet_extras = self.forward_transfer_packet(
            None,
            packet,
            fwd_metadata,
            original_sender,
            override_receiver,
            target_coin,
        )?;

        Ok(join_module_extras(
            receive_funds_extras,
            forward_transfer_packet_extras,
        ))
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

fn get_receiver<C: PfmContext>(
    ctx: &C,
    channel: &ChannelId,
    original_sender: &Signer,
) -> Result<Signer, MiddlewareError> {
    ctx.override_receiver(channel, original_sender)
        .map_err(|err| MiddlewareError::Message(format!("Failed to get override receiver: {err}")))
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

fn join_module_extras(mut first: ModuleExtras, mut second: ModuleExtras) -> ModuleExtras {
    first.events.append(&mut second.events);
    first.log.append(&mut second.log);
    first
}

fn retrieve_inflight_packet(
    inflight_packet: Option<InFlightPacket>,
    original_sender: Signer,
    src_packet: &Packet,
    retries: NonZeroU8,
    timeout: dur::Duration,
) -> InFlightPacket {
    if let Some(pkt) = inflight_packet {
        let retries_remaining = {
            debug_assert!(pkt.retries_remaining.get() > 0);

            NonZeroU8::new(pkt.retries_remaining.get().wrapping_sub(1))
                .expect("Number of retries was asserted to be greater than zero")
        };

        InFlightPacket {
            retries_remaining,
            ..pkt
        }
    } else {
        InFlightPacket {
            original_sender_address: original_sender,
            refund_port_id: src_packet.port_id_on_b.clone(),
            refund_channel_id: src_packet.chan_id_on_b.clone(),
            packet_src_port_id: src_packet.port_id_on_a.clone(),
            packet_src_channel_id: src_packet.chan_id_on_a.clone(),
            packet_timeout_timestamp: src_packet.timeout_timestamp_on_b,
            packet_timeout_height: src_packet.timeout_height_on_b,
            packet_data: src_packet.data.clone(),
            refund_sequence: src_packet.seq_on_a,
            retries_remaining: retries,
            timeout: msg::Duration::from_dur(timeout),
        }
    }
}

fn push_event_attr(attributes: &mut Vec<ModuleEventAttribute>, key: String, value: String) {
    attributes.push(ModuleEventAttribute { key, value });
}

fn emit_event_with_attrs(extras: &mut ModuleExtras, attributes: Vec<ModuleEventAttribute>) {
    extras.events.push(ModuleEvent {
        kind: MODULE.to_owned(),
        attributes,
    });
}
