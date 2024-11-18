//! Rust implementation of the IBC packet forwarding middleware.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

mod msg;
mod state;

use alloc::format;
use alloc::vec::Vec;
use core::fmt;
use core::num::NonZeroU8;

use either::*;
use ibc_app_transfer_types::msgs::transfer::MsgTransfer;
use ibc_app_transfer_types::packet::PacketData;
use ibc_app_transfer_types::{Coin, PrefixedDenom};
use ibc_core_channel_types::acknowledgement::{
    Acknowledgement, AcknowledgementStatus, StatusValue as AckStatusValue,
};
use ibc_core_channel_types::channel::{Counterparty, Order};
use ibc_core_channel_types::error::{ChannelError, PacketError};
use ibc_core_channel_types::packet::Packet;
use ibc_core_channel_types::timeout::{TimeoutHeight, TimeoutTimestamp};
use ibc_core_channel_types::Version;
use ibc_core_host_types::identifiers::{ChannelId, ConnectionId, PortId, Sequence};
use ibc_core_router::module::Module as IbcCoreModule;
use ibc_core_router_types::event::{ModuleEvent, ModuleEventAttribute};
use ibc_core_router_types::module::ModuleExtras;
use ibc_primitives::prelude::*;
use ibc_primitives::Signer;

#[doc(inline)]
pub use self::msg::Duration;
#[doc(inline)]
pub use self::state::{InFlightPacket, InFlightPacketKey};

pub type RetryInFlightPacket = InFlightPacket;

struct NewInFlightPacket<'pkt> {
    src_packet: &'pkt Packet,
    transfer_pkt: PacketData,
    original_sender: Signer,
    retries: NonZeroU8,
    timeout: dur::Duration,
}

enum RetryOutcome {
    /// We should retry submitting the in-flight packet.
    GoAhead,
    /// The maximum number of retries for a packet were exceeded.
    MaxRetriesExceeded,
}

#[derive(Debug)]
enum MiddlewareError {
    /// Error message.
    Message(String),
    /// Forward the call to the next middleware.
    ForwardToNextMiddleware,
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

    /// Execute an ICS-20 transfer. This method returns the [`Sequence`]
    /// of the sent packet.
    fn send_transfer_execute(&mut self, msg: MsgTransfer) -> Result<Sequence, Self::Error>;

    /// Handle receiving a refund from the next hop.
    /// This involves minting or unescrowing tokens on this chain.
    fn receive_refund_execute(
        &mut self,
        packet_forwarded_by_pfm_to_next_hop: &Packet,
        transfer_forwarded_by_pfm_to_next_hop: PacketData,
    ) -> Result<(), Self::Error>;

    /// Handle sending a refund back to the previous hop.
    /// This involves burning or escrowing tokens on this chain.
    fn send_refund_execute(
        &mut self,
        packet_from_previous_hop_sent_to_pfm: &InFlightPacket,
    ) -> Result<(), Self::Error>;

    /// Write the `acknowledgement` of `packet`, and emit events.
    fn write_ack_and_events(
        &mut self,
        packet: &Packet,
        acknowledgement: &Acknowledgement,
    ) -> Result<(), Self::Error>;

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
    fn store_inflight_packet(
        &mut self,
        key: InFlightPacketKey,
        inflight_packet: InFlightPacket,
    ) -> Result<(), Self::Error>;

    /// Retrieve an [in-flight packet](InFlightPacket) from storage.
    fn retrieve_inflight_packet(
        &self,
        key: &InFlightPacketKey,
    ) -> Result<Option<InFlightPacket>, Self::Error>;

    /// Delete an [in-flight packet](InFlightPacket) from storage.
    fn delete_inflight_packet(&mut self, key: &InFlightPacketKey) -> Result<(), Self::Error>;

    /// Get the denomination of `source_denom` for this chain,
    /// either involving wrapping or unwrapping of tokens.
    fn get_denom_for_this_chain(
        &self,
        this_chain_port: &PortId,
        this_chain_chan: &ChannelId,
        source_port: &PortId,
        source_chan: &ChannelId,
        source_denom: &PrefixedDenom,
    ) -> Result<PrefixedDenom, Self::Error>;
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
    #[allow(clippy::too_many_arguments)]
    fn forward_transfer_packet(
        &mut self,
        extras: &mut ModuleExtras,
        packet: Either<(&Packet, PacketData), RetryInFlightPacket>,
        fwd_metadata: msg::ForwardMetadata,
        original_sender: Signer,
        override_receiver: Signer,
        token_and_amount: Coin<PrefixedDenom>,
    ) -> Result<(), MiddlewareError> {
        let timeout = fwd_metadata
            .timeout
            .map_or(DEFAULT_FORWARD_TIMEOUT, |msg::Duration(d)| d);
        let retries = fwd_metadata.retries.unwrap_or(DEFAULT_FORWARD_RETRIES);

        emit_event_with_attrs(extras, {
            let mut attributes = Vec::with_capacity(8);

            push_event_attr(
                &mut attributes,
                "is-retry".to_owned(),
                packet.is_right().to_string(),
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
        });

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
            port_id_on_a: fwd_metadata.port.clone(),
            chan_id_on_a: fwd_metadata.channel.clone(),
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

        let sequence = self
            .next
            .send_transfer_execute(fwd_msg_transfer)
            .map_err(|err| {
                MiddlewareError::Message(format!("Failed to send forward packet: {err}"))
            })?;

        self.next
            .store_inflight_packet(
                InFlightPacketKey {
                    port: fwd_metadata.port,
                    channel: fwd_metadata.channel,
                    sequence,
                },
                next_inflight_packet(packet.map_left(|(src_packet, transfer_pkt)| {
                    NewInFlightPacket {
                        src_packet,
                        transfer_pkt,
                        original_sender,
                        retries,
                        timeout,
                    }
                })),
            )
            .map_err(|err| {
                MiddlewareError::Message(format!("Failed to store in-flight packet: {err}"))
            })?;

        emit_event_with_attrs(
            extras,
            vec![event_attr(
                "info".to_owned(),
                "Packet has been successfully forwarded".to_owned(),
            )],
        );

        Ok(())
    }

    fn receive_funds(
        &mut self,
        extras: &mut ModuleExtras,
        source_packet: &Packet,
        source_transfer_pkt: PacketData,
        override_receiver: Signer,
        relayer: &Signer,
    ) -> Result<(), MiddlewareError> {
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

        let maybe_ack = {
            let (next_extras, maybe_ack) =
                self.next.on_recv_packet_execute(&override_packet, relayer);
            join_module_extras(extras, next_extras);
            maybe_ack
        };

        let Some(ack) = maybe_ack else {
            return Err(MiddlewareError::Message("Ack is nil".to_owned()));
        };

        let ack: AcknowledgementStatus = serde_json::from_slice(ack.as_bytes())
            .map_err(|err| MiddlewareError::Message(format!("Failed to parse ack: {err}")))?;

        if ack.is_successful() {
            Ok(())
        } else {
            Err(MiddlewareError::Message(format!("Ack error: {ack}")))
        }
    }

    fn write_acknowledgement_for_forwarded_packet(
        &mut self,
        packet: &Packet,
        transfer_pkt: PacketData,
        inflight_packet: InFlightPacket,
        acknowledgement: &Acknowledgement,
    ) -> Result<(), MiddlewareError> {
        self.next
            .receive_refund_execute(packet, transfer_pkt)
            .map_err(|err| {
                MiddlewareError::Message(format!(
                    "Failed to refund transfer sent to next hop: {err}"
                ))
            })?;

        self.next
            .send_refund_execute(&inflight_packet)
            .map_err(|err| {
                MiddlewareError::Message(format!(
                    "Failed to refund transfer received from previous hop: {err}"
                ))
            })?;

        self.next
            .write_ack_and_events(&inflight_packet.into(), acknowledgement)
            .map_err(|err| {
                MiddlewareError::Message(format!(
                    "Failed to write acknowledgement of in-flight packet: {err}"
                ))
            })?;

        Ok(())
    }

    fn timeout_should_retry(
        &self,
        packet: &Packet,
    ) -> Result<(RetryOutcome, InFlightPacket), MiddlewareError> {
        let inflight_packet_key = InFlightPacketKey {
            port: packet.port_id_on_a.clone(),
            channel: packet.chan_id_on_a.clone(),
            sequence: packet.seq_on_a,
        };

        let inflight_packet = self
            .next
            .retrieve_inflight_packet(&inflight_packet_key)
            .map_err(|err| {
                MiddlewareError::Message(format!(
                    "Failed to retrieve in-flight packet from storage: {err}"
                ))
            })?
            .ok_or(MiddlewareError::ForwardToNextMiddleware)?;

        let outcome = if inflight_packet.retries_remaining.is_some() {
            RetryOutcome::GoAhead
        } else {
            RetryOutcome::MaxRetriesExceeded
        };

        Ok((outcome, inflight_packet))
    }

    fn retry_timeout(
        &mut self,
        extras: &mut ModuleExtras,
        port: &PortId,
        channel: &ChannelId,
        transfer_pkt: PacketData,
        inflight_packet: InFlightPacket,
    ) -> Result<(), MiddlewareError> {
        let next = {
            let memo = transfer_pkt.memo.as_ref();

            if !memo.is_empty() {
                let json_obj_memo: serde_json::Map<String, serde_json::Value> =
                    serde_json::from_str(memo).map_err(|err| {
                        MiddlewareError::Message(format!("Failed to decode next memo: {err}"))
                    })?;
                Some(json_obj_memo)
            } else {
                None
            }
        };
        let fwd_metadata = msg::ForwardMetadata {
            receiver: transfer_pkt.receiver,
            port: port.clone(),
            channel: channel.clone(),
            timeout: Some(inflight_packet.timeout.clone()),
            retries: {
                debug_assert!(
                    inflight_packet.retries_remaining.is_some(),
                    "We should only hit this branch with at least one retry remaining"
                );
                inflight_packet.retries_remaining
            },
            next,
        };

        let original_sender = inflight_packet.original_sender_address.clone();
        let override_receiver = transfer_pkt.sender;
        let token_and_amount = transfer_pkt.token;

        self.forward_transfer_packet(
            extras,
            Right(inflight_packet),
            fwd_metadata,
            original_sender,
            override_receiver,
            token_and_amount,
        )
    }

    fn on_recv_packet_execute_inner(
        &mut self,
        extras: &mut ModuleExtras,
        packet: &Packet,
        relayer: &Signer,
    ) -> Result<(), MiddlewareError> {
        let (transfer_pkt, fwd_metadata) = decode_forward_msg(packet)?;

        let override_receiver =
            get_receiver(&self.next, &packet.chan_id_on_b, &transfer_pkt.sender)?;
        let denom_on_this_chain = self
            .next
            .get_denom_for_this_chain(
                &packet.port_id_on_b,
                &packet.chan_id_on_b,
                &packet.port_id_on_a,
                &packet.chan_id_on_a,
                &transfer_pkt.token.denom,
            )
            .map_err(|err| {
                MiddlewareError::Message(format!("Failed to get coin denom for this chain: {err}"))
            })?;
        let coin_on_this_chain = Coin {
            denom: denom_on_this_chain,
            amount: transfer_pkt.token.amount,
        };
        let original_sender = transfer_pkt.sender.clone();

        self.receive_funds(
            extras,
            packet,
            transfer_pkt.clone(),
            override_receiver.clone(),
            relayer,
        )?;
        self.forward_transfer_packet(
            extras,
            Left((packet, transfer_pkt)),
            fwd_metadata,
            original_sender,
            override_receiver,
            coin_on_this_chain,
        )?;

        Ok(())
    }

    fn on_acknowledgement_packet_execute_inner(
        &mut self,
        extras: &mut ModuleExtras,
        packet: &Packet,
        acknowledgement: &Acknowledgement,
    ) -> Result<(), MiddlewareError> {
        let transfer_pkt = decode_ics20_msg(packet)?;

        let inflight_packet_key = InFlightPacketKey {
            port: packet.port_id_on_a.clone(),
            channel: packet.chan_id_on_a.clone(),
            sequence: packet.seq_on_a,
        };

        let inflight_packet = self
            .next
            .retrieve_inflight_packet(&inflight_packet_key)
            .map_err(|err| {
                MiddlewareError::Message(format!(
                    "Failed to retrieve in-flight packet from storage: {err}"
                ))
            })?
            .ok_or(MiddlewareError::ForwardToNextMiddleware)?;

        self.next
            .delete_inflight_packet(&inflight_packet_key)
            .map_err(|err| {
                MiddlewareError::Message(format!(
                    "Failed to delete in-flight packet from storage: {err}"
                ))
            })?;

        self.write_acknowledgement_for_forwarded_packet(
            packet,
            transfer_pkt,
            inflight_packet,
            acknowledgement,
        )?;

        emit_event_with_attrs(
            extras,
            vec![event_attr(
                "info".to_owned(),
                "Packet acknowledgement processed successfully".to_owned(),
            )],
        );

        Ok(())
    }

    fn on_timeout_packet_execute_inner(
        &mut self,
        extras: &mut ModuleExtras,
        packet: &Packet,
        relayer: &Signer,
    ) -> Result<(), MiddlewareError> {
        let transfer_pkt = decode_ics20_msg(packet)?;

        match self.timeout_should_retry(packet)? {
            (RetryOutcome::GoAhead, inflight_packet) => {
                let (next_extras, result) = self.next.on_timeout_packet_execute(packet, relayer);

                join_module_extras(extras, next_extras);
                result.map_err(|err| {
                    MiddlewareError::Message(format!(
                        "Failed to retry packet, while invoking \
                         on_timeout_packet_execute: {err}"
                    ))
                })?;

                self.retry_timeout(
                    extras,
                    &packet.port_id_on_a,
                    &packet.chan_id_on_a,
                    transfer_pkt,
                    inflight_packet,
                )
            }
            (RetryOutcome::MaxRetriesExceeded, inflight_packet) => {
                let inflight_packet_key = InFlightPacketKey {
                    port: packet.port_id_on_a.clone(),
                    channel: packet.chan_id_on_a.clone(),
                    sequence: packet.seq_on_a,
                };

                self.next
                    .delete_inflight_packet(&inflight_packet_key)
                    .map_err(|err| {
                        MiddlewareError::Message(format!(
                            "Failed to delete in-flight packet from storage: {err}"
                        ))
                    })?;

                let acknowledgement = {
                    let InFlightPacket {
                        refund_sequence,
                        refund_port_id,
                        refund_channel_id,
                        ..
                    } = &inflight_packet;

                    new_error_ack(format!(
                        "In-flight packet max retries exceeded, for packet with sequence \
                         {refund_sequence} on {refund_port_id}/{refund_channel_id}"
                    ))
                    .into()
                };

                self.write_acknowledgement_for_forwarded_packet(
                    packet,
                    transfer_pkt,
                    inflight_packet,
                    &acknowledgement,
                )
            }
        }
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
        let mut extras = ModuleExtras::empty();

        match self.on_recv_packet_execute_inner(&mut extras, packet, relayer) {
            Ok(()) => (extras, None),
            Err(MiddlewareError::ForwardToNextMiddleware) => {
                self.next.on_recv_packet_execute(packet, relayer)
            }
            Err(MiddlewareError::Message(err)) => (extras, Some(new_error_ack(err).into())),
        }
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
        let mut extras = ModuleExtras::empty();

        match self.on_acknowledgement_packet_execute_inner(&mut extras, packet, acknowledgement) {
            Ok(()) => (extras, Ok(())),
            Err(MiddlewareError::ForwardToNextMiddleware) => self
                .next
                .on_acknowledgement_packet_execute(packet, acknowledgement, relayer),
            Err(MiddlewareError::Message(err)) => (extras, new_packet_error(err)),
        }
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
        let mut extras = ModuleExtras::empty();

        match self.on_timeout_packet_execute_inner(&mut extras, packet, relayer) {
            Ok(()) => (extras, Ok(())),
            Err(MiddlewareError::ForwardToNextMiddleware) => {
                self.next.on_timeout_packet_execute(packet, relayer)
            }
            Err(MiddlewareError::Message(err)) => (extras, new_packet_error(err)),
        }
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

#[inline]
fn new_packet_error(message: impl fmt::Display) -> Result<(), PacketError> {
    Err(PacketError::Other {
        description: format!("{MODULE} error: {message}"),
    })
}

fn get_receiver<C: PfmContext>(
    ctx: &C,
    channel: &ChannelId,
    original_sender: &Signer,
) -> Result<Signer, MiddlewareError> {
    ctx.override_receiver(channel, original_sender)
        .map_err(|err| MiddlewareError::Message(format!("Failed to get override receiver: {err}")))
}

fn decode_ics20_msg(packet: &Packet) -> Result<PacketData, MiddlewareError> {
    serde_json::from_slice(&packet.data).map_err(|_| {
        // NB: if `packet.data` is not a valid fungible token transfer
        // packet, we forward the call to the next middleware
        MiddlewareError::ForwardToNextMiddleware
    })
}

fn decode_forward_msg(
    packet: &Packet,
) -> Result<(PacketData, msg::ForwardMetadata), MiddlewareError> {
    let transfer_pkt = decode_ics20_msg(packet)?;

    let json_obj_memo: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(transfer_pkt.memo.as_ref()).map_err(|_| {
            // NB: if the ICS-20 packet memo is not a valid JSON object, we forward
            // this call to the next middleware
            MiddlewareError::ForwardToNextMiddleware
        })?;

    if !json_obj_memo.contains_key("forward") {
        // NB: the memo was a valid json object, but it wasn't up to
        // the PFM to consume it, so we forward the call to the next middleware
        return Err(MiddlewareError::ForwardToNextMiddleware);
    }

    serde_json::from_value(json_obj_memo.into()).map_or_else(
        |err| Err(MiddlewareError::Message(err.to_string())),
        |msg::PacketMetadata { forward }| Ok((transfer_pkt, forward)),
    )
}

fn join_module_extras(first: &mut ModuleExtras, mut second: ModuleExtras) {
    first.events.append(&mut second.events);
    first.log.append(&mut second.log);
}

fn next_inflight_packet(
    packet: Either<NewInFlightPacket<'_>, RetryInFlightPacket>,
) -> InFlightPacket {
    packet.either(
        |NewInFlightPacket {
             src_packet,
             transfer_pkt,
             original_sender,
             retries,
             timeout,
         }| InFlightPacket {
            original_sender_address: original_sender,
            refund_port_id: src_packet.port_id_on_b.clone(),
            refund_channel_id: src_packet.chan_id_on_b.clone(),
            packet_src_port_id: src_packet.port_id_on_a.clone(),
            packet_src_channel_id: src_packet.chan_id_on_a.clone(),
            packet_timeout_timestamp: src_packet.timeout_timestamp_on_b,
            packet_timeout_height: src_packet.timeout_height_on_b,
            packet_data: transfer_pkt,
            refund_sequence: src_packet.seq_on_a,
            retries_remaining: Some(retries),
            timeout: msg::Duration::from_dur(timeout),
        },
        |inflight_packet| {
            let retries_remaining = {
                NonZeroU8::new(
                    inflight_packet
                        .retries_remaining
                        .expect("We should only hit this branch with at least one retry remaining")
                        .get()
                        .wrapping_sub(1),
                )
            };

            RetryInFlightPacket {
                retries_remaining,
                ..inflight_packet
            }
        },
    )
}

#[inline]
fn event_attr(key: String, value: String) -> ModuleEventAttribute {
    ModuleEventAttribute { key, value }
}

#[inline]
fn push_event_attr(attributes: &mut Vec<ModuleEventAttribute>, key: String, value: String) {
    attributes.push(event_attr(key, value));
}

#[inline]
fn emit_event_with_attrs(extras: &mut ModuleExtras, attributes: Vec<ModuleEventAttribute>) {
    extras.events.push(ModuleEvent {
        kind: MODULE.to_owned(),
        attributes,
    });
}

#[cfg(test)]
mod tests {
    use ibc_testkit::fixtures::core::channel::dummy_raw_packet;

    use super::{test_utils::*, *};

    #[test]
    fn decode_ics20_msg_forwards_to_next_middleware() {
        // NB: this packet doesn't have ICS-20 packet data
        let packet: Packet = dummy_raw_packet(0, 1).try_into().unwrap();
        assert!(matches!(
            decode_ics20_msg(&packet),
            Err(MiddlewareError::ForwardToNextMiddleware)
        ));
    }

    #[test]
    fn decode_ics20_msg_on_valid_ics20_data() {
        let expected_packet_data = get_dummy_packet_data(100);
        let packet = get_dummy_packet_with_data(0, &expected_packet_data);

        let got_packet_data = decode_ics20_msg(&packet).unwrap();
        assert_eq!(got_packet_data, expected_packet_data);
    }

    #[test]
    fn decode_forward_msg_forwards_to_next_middleware_not_json() {
        let packet_data = get_dummy_packet_data_with_memo(100, "oh hi mark".to_owned());
        let packet = get_dummy_packet_with_data(0, &packet_data);

        assert!(matches!(
            decode_forward_msg(&packet),
            Err(MiddlewareError::ForwardToNextMiddleware)
        ));
    }

    #[test]
    fn decode_forward_msg_forwards_to_next_middleware_not_pfm_msg() {
        let packet_data =
            get_dummy_packet_data_with_memo(100, r#"{"combo": "breaker"}"#.to_owned());
        let packet = get_dummy_packet_with_data(0, &packet_data);

        assert!(matches!(
            decode_forward_msg(&packet),
            Err(MiddlewareError::ForwardToNextMiddleware)
        ));
    }

    #[test]
    fn decode_forward_msg_failure() {
        let packet_data =
            get_dummy_packet_data_with_memo(100, r#"{"forward": {"foot": "best"}}"#.to_owned());
        let packet = get_dummy_packet_with_data(0, &packet_data);

        assert!(matches!(
            decode_forward_msg(&packet),
            Err(MiddlewareError::Message(_))
        ));
    }

    #[test]
    fn decode_forward_msg_success() {
        let expected_fwd_metadata = msg::PacketMetadata {
            forward: get_dummy_fwd_metadata(),
        };
        let expected_packet_data = get_dummy_packet_data_with_memo(
            100,
            serde_json::to_string(&expected_fwd_metadata).unwrap(),
        );

        let packet = get_dummy_packet_with_data(0, &expected_packet_data);
        let (got_packet_data, got_fwd_metadata) = decode_forward_msg(&packet).unwrap();

        assert_eq!(expected_packet_data, got_packet_data);
        assert_eq!(expected_fwd_metadata.forward, got_fwd_metadata);
    }

    #[test]
    fn next_inflight_packet_decreases_retries() {
        let retries = NonZeroU8::new(2).unwrap();

        let first_inflight_packet = InFlightPacket {
            original_sender_address: String::new().into(),
            refund_port_id: PortId::transfer(),
            refund_channel_id: ChannelId::new(channels::BA),
            packet_src_port_id: PortId::transfer(),
            packet_src_channel_id: ChannelId::new(channels::AB),
            packet_timeout_timestamp: TimeoutTimestamp::Never,
            packet_timeout_height: TimeoutHeight::Never,
            packet_data: get_dummy_packet_data(100),
            refund_sequence: 0u64.into(),
            retries_remaining: Some(retries),
            timeout: msg::Duration::from_dur(DEFAULT_FORWARD_TIMEOUT),
        };

        let mut second_inflight_packet = next_inflight_packet(Right(first_inflight_packet.clone()));

        second_inflight_packet.retries_remaining = second_inflight_packet
            .retries_remaining
            .as_mut()
            .unwrap()
            .checked_add(1);

        assert_eq!(first_inflight_packet, second_inflight_packet);
    }

    #[test]
    fn next_inflight_packet_from_packet() {
        let packet_data = get_dummy_packet_data(100);
        let packet = Packet {
            data: serde_json::to_vec(&packet_data).unwrap(),
            port_id_on_b: PortId::transfer(),
            chan_id_on_b: ChannelId::new(channels::BA),
            port_id_on_a: PortId::transfer(),
            chan_id_on_a: ChannelId::new(channels::AB),
            timeout_height_on_b: TimeoutHeight::Never,
            timeout_timestamp_on_b: TimeoutTimestamp::Never,
            seq_on_a: 0u64.into(),
        };

        let got_inflight_packet = next_inflight_packet(Left(NewInFlightPacket {
            src_packet: &packet,
            transfer_pkt: packet_data,
            original_sender: String::new().into(),
            retries: DEFAULT_FORWARD_RETRIES,
            timeout: DEFAULT_FORWARD_TIMEOUT,
        }));

        let expected_inflight_packet = InFlightPacket {
            original_sender_address: String::new().into(),
            refund_port_id: PortId::transfer(),
            refund_channel_id: ChannelId::new(channels::BA),
            packet_src_port_id: PortId::transfer(),
            packet_src_channel_id: ChannelId::new(channels::AB),
            packet_timeout_timestamp: TimeoutTimestamp::Never,
            packet_timeout_height: TimeoutHeight::Never,
            packet_data: get_dummy_packet_data(100),
            refund_sequence: 0u64.into(),
            retries_remaining: Some(DEFAULT_FORWARD_RETRIES),
            timeout: msg::Duration::from_dur(DEFAULT_FORWARD_TIMEOUT),
        };

        assert_eq!(got_inflight_packet, expected_inflight_packet);
    }

    #[test]
    fn module_extras_appending() {
        let mut first_extras = ModuleExtras::empty();
        let mut second_extras = ModuleExtras::empty();

        emit_event_with_attrs(&mut first_extras, {
            let mut attributes = Vec::with_capacity(8);
            push_event_attr(&mut attributes, "1".to_owned(), String::new());
            attributes
        });
        emit_event_with_attrs(&mut second_extras, {
            let mut attributes = Vec::with_capacity(8);
            push_event_attr(&mut attributes, "2".to_owned(), String::new());
            attributes
        });

        let extras = {
            join_module_extras(&mut first_extras, second_extras);
            first_extras
        };

        assert!(extras.log.is_empty());
        assert_eq!(
            extras
                .events
                .iter()
                .flat_map(|e| e.attributes.iter().map(|at| &at.key))
                .collect::<Vec<_>>(),
            ["1", "2"]
        );
    }

    #[test]
    fn events_kept_on_errors() {
        let mut pfm = get_dummy_pfm();
        pfm.inject_failure(FailurePoint::SendTransferExecute);

        let mut extras = ModuleExtras::empty();

        let packet_data = get_dummy_packet_data(100);
        let packet = get_dummy_packet_with_data(0, &packet_data);
        let fwd_metadata = get_dummy_fwd_metadata();

        let denom_on_this_chain = pfm
            .next
            .get_denom_for_this_chain(
                &packet.port_id_on_b,
                &packet.chan_id_on_b,
                &packet.port_id_on_a,
                &packet.chan_id_on_a,
                &packet_data.token.denom,
            )
            .unwrap();
        let coin_on_this_chain = Coin {
            denom: denom_on_this_chain,
            amount: packet_data.token.amount,
        };

        let expected_extras = {
            let mut ex = ModuleExtras::empty();
            emit_event_with_attrs(&mut ex, {
                let mut attributes = Vec::with_capacity(8);
                push_event_attr(&mut attributes, "is-retry".to_owned(), false.to_string());
                push_event_attr(
                    &mut attributes,
                    "escrow-account".to_owned(),
                    "Barbara".to_string(),
                );
                push_event_attr(&mut attributes, "sender".to_owned(), "Bob".to_string());
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
            });
            ex
        };

        assert_failure_injection(
            FailurePoint::SendTransferExecute,
            pfm.forward_transfer_packet(
                &mut extras,
                Left((&packet, packet_data)),
                fwd_metadata,
                String::from("Bob").into(),
                String::from("Barbara").into(),
                coin_on_this_chain,
            ),
        );

        assert_eq!(extras.log, expected_extras.log);
        assert_eq!(extras.events, expected_extras.events);
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod test_utils {
    use std::collections::{HashMap, HashSet};

    use ibc_app_transfer_types::{TracePath, TracePrefix};
    use ibc_primitives::Timestamp;
    use ibc_testkit::testapp::ibc::applications::transfer::types::DummyTransferModule;

    use super::*;

    // NOTE: Assume we have three chains: A, B, and C. The tests will be set
    // up as if we were chain B, forwarding a packet from A to C.
    pub mod channels {
        // Outgoing channels from A.
        pub const AB: u64 = 0;

        // Outgoing channels from B.
        pub const BA: u64 = 2;
        pub const BC: u64 = 3;

        // Outgoing channels from C.
        pub const CB: u64 = 5;
    }

    pub mod base_denoms {
        pub const A: &str = "uauauiua";
        pub const B: &str = "ubongus";
        pub const C: &str = "uchungus";
    }

    pub const ESCROW_ACCOUNT: &str = "ics-ics20-escrow-account";

    #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
    pub enum FailurePoint {
        SendTransferExecute,
    }

    #[derive(Debug)]
    pub struct Store<M> {
        middleware: M,
        failure_injections: HashSet<FailurePoint>,
        pub inflight_packet_store: HashMap<InFlightPacketKey, InFlightPacket>,
        pub sent_transfers: Vec<MsgTransfer>,
        pub refunds_received: Vec<(Packet, PacketData)>,
        pub refunds_sent: Vec<InFlightPacket>,
        pub ack_and_events_written: Vec<(Packet, Acknowledgement)>,
    }

    impl<M> Store<M> {
        pub fn new(middleware: M) -> Self {
            Self {
                middleware,
                inflight_packet_store: HashMap::new(),
                sent_transfers: Vec::new(),
                refunds_received: Vec::new(),
                refunds_sent: Vec::new(),
                ack_and_events_written: Vec::new(),
                failure_injections: HashSet::new(),
            }
        }

        fn check_failure_injection(&self, point: FailurePoint) -> Result<(), String> {
            if !self.failure_injections.contains(&point) {
                Ok(())
            } else {
                Err(failure_injection_err_msg(point))
            }
        }
    }

    impl<M> IbcCoreModule for Store<M>
    where
        M: IbcCoreModule,
    {
        fn on_recv_packet_execute(
            &mut self,
            packet: &Packet,
            relayer: &Signer,
        ) -> (ModuleExtras, Option<Acknowledgement>) {
            self.middleware.on_recv_packet_execute(packet, relayer)
        }

        fn on_acknowledgement_packet_validate(
            &self,
            packet: &Packet,
            acknowledgement: &Acknowledgement,
            relayer: &Signer,
        ) -> Result<(), PacketError> {
            self.middleware
                .on_acknowledgement_packet_validate(packet, acknowledgement, relayer)
        }

        fn on_acknowledgement_packet_execute(
            &mut self,
            packet: &Packet,
            acknowledgement: &Acknowledgement,
            relayer: &Signer,
        ) -> (ModuleExtras, Result<(), PacketError>) {
            self.middleware
                .on_acknowledgement_packet_execute(packet, acknowledgement, relayer)
        }

        fn on_timeout_packet_validate(
            &self,
            packet: &Packet,
            relayer: &Signer,
        ) -> Result<(), PacketError> {
            self.middleware.on_timeout_packet_validate(packet, relayer)
        }

        fn on_timeout_packet_execute(
            &mut self,
            packet: &Packet,
            relayer: &Signer,
        ) -> (ModuleExtras, Result<(), PacketError>) {
            self.middleware.on_timeout_packet_execute(packet, relayer)
        }

        fn on_chan_open_init_validate(
            &self,
            order: Order,
            connection_hops: &[ConnectionId],
            port_id: &PortId,
            channel_id: &ChannelId,
            counterparty: &Counterparty,
            version: &Version,
        ) -> Result<Version, ChannelError> {
            self.middleware.on_chan_open_init_validate(
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
            self.middleware.on_chan_open_init_execute(
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
            self.middleware.on_chan_open_try_validate(
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
            self.middleware.on_chan_open_try_execute(
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
            self.middleware
                .on_chan_open_ack_validate(port_id, channel_id, counterparty_version)
        }

        fn on_chan_open_ack_execute(
            &mut self,
            port_id: &PortId,
            channel_id: &ChannelId,
            counterparty_version: &Version,
        ) -> Result<ModuleExtras, ChannelError> {
            self.middleware
                .on_chan_open_ack_execute(port_id, channel_id, counterparty_version)
        }

        fn on_chan_open_confirm_validate(
            &self,
            port_id: &PortId,
            channel_id: &ChannelId,
        ) -> Result<(), ChannelError> {
            self.middleware
                .on_chan_open_confirm_validate(port_id, channel_id)
        }

        fn on_chan_open_confirm_execute(
            &mut self,
            port_id: &PortId,
            channel_id: &ChannelId,
        ) -> Result<ModuleExtras, ChannelError> {
            self.middleware
                .on_chan_open_confirm_execute(port_id, channel_id)
        }

        fn on_chan_close_init_validate(
            &self,
            port_id: &PortId,
            channel_id: &ChannelId,
        ) -> Result<(), ChannelError> {
            self.middleware
                .on_chan_close_init_validate(port_id, channel_id)
        }

        fn on_chan_close_init_execute(
            &mut self,
            port_id: &PortId,
            channel_id: &ChannelId,
        ) -> Result<ModuleExtras, ChannelError> {
            self.middleware
                .on_chan_close_init_execute(port_id, channel_id)
        }

        fn on_chan_close_confirm_validate(
            &self,
            port_id: &PortId,
            channel_id: &ChannelId,
        ) -> Result<(), ChannelError> {
            self.middleware
                .on_chan_close_confirm_validate(port_id, channel_id)
        }

        fn on_chan_close_confirm_execute(
            &mut self,
            port_id: &PortId,
            channel_id: &ChannelId,
        ) -> Result<ModuleExtras, ChannelError> {
            self.middleware
                .on_chan_close_confirm_execute(port_id, channel_id)
        }
    }

    impl<M> PfmContext for Store<M> {
        type Error = String;

        fn send_transfer_execute(&mut self, msg: MsgTransfer) -> Result<Sequence, Self::Error> {
            self.check_failure_injection(FailurePoint::SendTransferExecute)?;
            let seq = Sequence::from(self.sent_transfers.len() as u64);
            self.sent_transfers.push(msg);
            Ok(seq)
        }

        fn receive_refund_execute(
            &mut self,
            packet: &Packet,
            transfer_pkt: PacketData,
        ) -> Result<(), Self::Error> {
            self.refunds_received.push((packet.clone(), transfer_pkt));
            Ok(())
        }

        fn send_refund_execute(
            &mut self,
            inflight_packet: &InFlightPacket,
        ) -> Result<(), Self::Error> {
            self.refunds_sent.push(inflight_packet.clone());
            Ok(())
        }

        fn write_ack_and_events(
            &mut self,
            packet: &Packet,
            acknowledgement: &Acknowledgement,
        ) -> Result<(), Self::Error> {
            self.ack_and_events_written
                .push((packet.clone(), acknowledgement.clone()));
            Ok(())
        }

        fn override_receiver(
            &self,
            _channel: &ChannelId,
            _original_sender: &Signer,
        ) -> Result<Signer, Self::Error> {
            Ok(ESCROW_ACCOUNT.to_string().into())
        }

        fn timeout_timestamp(
            &self,
            timeout_duration: dur::Duration,
        ) -> Result<TimeoutTimestamp, Self::Error> {
            let nanos: u64 = timeout_duration.as_nanos().try_into().map_err(|e| {
                format!("Could not convert duration {timeout_duration} to u64 nanos: {e}")
            })?;

            Ok(TimeoutTimestamp::At(Timestamp::from_nanoseconds(nanos)))
        }

        fn store_inflight_packet(
            &mut self,
            key: InFlightPacketKey,
            inflight_packet: InFlightPacket,
        ) -> Result<(), Self::Error> {
            self.inflight_packet_store.insert(key, inflight_packet);
            Ok(())
        }

        fn retrieve_inflight_packet(
            &self,
            key: &InFlightPacketKey,
        ) -> Result<Option<InFlightPacket>, Self::Error> {
            Ok(self.inflight_packet_store.get(key).cloned())
        }

        fn delete_inflight_packet(&mut self, key: &InFlightPacketKey) -> Result<(), Self::Error> {
            self.inflight_packet_store.remove(key);
            Ok(())
        }

        fn get_denom_for_this_chain(
            &self,
            this_chain_port: &PortId,
            this_chain_chan: &ChannelId,
            source_port: &PortId,
            source_chan: &ChannelId,
            source_denom: &PrefixedDenom,
        ) -> Result<PrefixedDenom, Self::Error> {
            let transfer_port = PortId::transfer();
            assert_eq!(this_chain_port, &transfer_port);
            assert_eq!(source_port, &transfer_port);

            let this_chain_chan: u64 = this_chain_chan
                .as_str()
                .strip_prefix("channel-")
                .unwrap()
                .parse()
                .unwrap();
            let source_chan: u64 = source_chan
                .as_str()
                .strip_prefix("channel-")
                .unwrap()
                .parse()
                .unwrap();

            assert_eq!((source_chan, this_chain_chan), (channels::AB, channels::BA));

            let trace_prefix = TracePrefix::new(transfer_port.clone(), ChannelId::new(source_chan));

            if source_denom.trace_path.starts_with(&trace_prefix) {
                // NB: we're either dealing with `base_denoms::B` or `base_denoms::C`.
                // we must unwrap `source_denom`.

                let this_chain_trace_path = {
                    let mut trace = source_denom.trace_path.clone();
                    trace.remove_prefix(&trace_prefix);
                    trace
                };

                Ok(PrefixedDenom {
                    base_denom: source_denom.base_denom.clone(),
                    trace_path: this_chain_trace_path,
                })
            } else {
                // NB: this has to be `base_denoms::A`. we must
                // wrap `source_denom`.

                assert!(source_denom.trace_path.is_empty());
                assert_eq!(source_denom.base_denom.as_str(), base_denoms::A);

                Ok(PrefixedDenom {
                    base_denom: base_denoms::A.parse().unwrap(),
                    trace_path: {
                        let mut trace = TracePath::empty();
                        trace.add_prefix(TracePrefix::new(
                            transfer_port,
                            ChannelId::new(this_chain_chan),
                        ));
                        trace
                    },
                })
            }
        }
    }

    impl<M> PacketForwardMiddleware<Store<M>> {
        pub fn inject_failure(&mut self, point: FailurePoint) {
            self.next.failure_injections.insert(point);
        }
    }

    #[track_caller]
    pub fn assert_failure_injection<T>(point: FailurePoint, result: Result<T, MiddlewareError>) {
        let caller = std::panic::Location::caller();

        let error_msg = match result {
            Ok(_) => {
                panic!(
                    "Panicked from {caller} due to failure injection \
                     assertion: Expected {point:?}, but no error was found"
                );
            }
            Err(MiddlewareError::ForwardToNextMiddleware) => {
                panic!(
                    "Panicked from {caller} due to failure injection \
                     assertion: Expected {point:?}, but we were trying \
                     to forward a call to the next middleware"
                );
            }
            Err(MiddlewareError::Message(error_msg)) => error_msg,
        };

        let expected_failure_point_err_msg = failure_injection_err_msg(point);
        let Some((_, got_failure_point_err_msg)) = error_msg.rsplit_once(": ") else {
            panic!(
                "Panicked from {caller} due to failure injection \
                 assertion: Expected {point:?}, but the error was \
                 different: {error_msg}"
            );
        };

        if got_failure_point_err_msg != expected_failure_point_err_msg {
            panic!(
                "Panicked from {caller} due to failure injection \
                 assertion: Expected {point:?}, but the error was \
                 different: {got_failure_point_err_msg}"
            );
        }
    }

    fn failure_injection_err_msg(point: FailurePoint) -> String {
        format!("Failure injection on {point:?}")
    }

    pub fn get_dummy_pfm() -> PacketForwardMiddleware<Store<DummyTransferModule>> {
        PacketForwardMiddleware::next(Store::new(DummyTransferModule::new()))
    }

    pub fn get_dummy_coin(amount: u64) -> Coin<PrefixedDenom> {
        let chan_id = channels::AB;
        let denom = base_denoms::B;

        Coin {
            denom: format!("transfer/channel-{chan_id}/{denom}")
                .parse()
                .unwrap(),
            amount: amount.into(),
        }
    }

    pub fn get_dummy_packet_data_with_memo(transfer_amount: u64, memo: String) -> PacketData {
        PacketData {
            sender: String::new().into(),
            receiver: String::new().into(),
            token: get_dummy_coin(transfer_amount),
            memo: memo.into(),
        }
    }

    pub fn get_dummy_packet_data(transfer_amount: u64) -> PacketData {
        get_dummy_packet_data_with_memo(transfer_amount, String::new())
    }

    pub fn get_dummy_packet_with_data(seq: u64, packet_data: &PacketData) -> Packet {
        Packet {
            data: serde_json::to_vec(packet_data).unwrap(),
            seq_on_a: seq.into(),
            port_id_on_a: PortId::transfer(),
            chan_id_on_a: ChannelId::new(channels::AB),
            port_id_on_b: PortId::transfer(),
            chan_id_on_b: ChannelId::new(channels::BA),
            timeout_height_on_b: TimeoutHeight::Never,
            timeout_timestamp_on_b: TimeoutTimestamp::Never,
        }
    }

    pub fn get_dummy_fwd_metadata() -> msg::ForwardMetadata {
        msg::ForwardMetadata {
            receiver: String::from("receiver").into(),
            port: PortId::transfer(),
            channel: ChannelId::new(channels::BC),
            timeout: None,
            retries: None,
            next: None,
        }
    }

    #[test]
    fn get_denom_for_this_chain_works_as_expected() {
        let pfm = get_dummy_pfm();

        let transfer_port = PortId::transfer();

        // A => B
        let source_denom = PrefixedDenom {
            base_denom: base_denoms::A.parse().unwrap(),
            trace_path: TracePath::empty(),
        };
        let expected_denom = PrefixedDenom {
            base_denom: base_denoms::A.parse().unwrap(),
            trace_path: {
                let mut trace = TracePath::empty();
                trace.add_prefix(TracePrefix::new(
                    transfer_port.clone(),
                    ChannelId::new(channels::BA),
                ));
                trace
            },
        };
        let got_denom = pfm
            .next
            .get_denom_for_this_chain(
                &transfer_port,
                &ChannelId::new(channels::BA),
                &transfer_port,
                &ChannelId::new(channels::AB),
                &source_denom,
            )
            .unwrap();
        assert_eq!(expected_denom, got_denom);

        // C => B => A => B
        let source_denom = PrefixedDenom {
            base_denom: base_denoms::C.parse().unwrap(),
            trace_path: {
                let mut trace = TracePath::empty();
                trace.add_prefix(TracePrefix::new(
                    transfer_port.clone(),
                    // landed on B
                    ChannelId::new(channels::BC),
                ));
                trace.add_prefix(TracePrefix::new(
                    transfer_port.clone(),
                    // landed on A
                    ChannelId::new(channels::AB),
                ));
                trace
            },
        };
        let expected_denom = PrefixedDenom {
            base_denom: base_denoms::C.parse().unwrap(),
            trace_path: {
                let mut trace = TracePath::empty();
                trace.add_prefix(TracePrefix::new(
                    transfer_port.clone(),
                    // landed on B
                    ChannelId::new(channels::BC),
                ));
                trace
            },
        };
        let got_denom = pfm
            .next
            .get_denom_for_this_chain(
                &transfer_port,
                &ChannelId::new(channels::BA),
                &transfer_port,
                &ChannelId::new(channels::AB),
                &source_denom,
            )
            .unwrap();
        assert_eq!(expected_denom, got_denom);

        // B => A => B
        let source_denom = PrefixedDenom {
            base_denom: base_denoms::B.parse().unwrap(),
            trace_path: {
                let mut trace = TracePath::empty();
                trace.add_prefix(TracePrefix::new(
                    transfer_port.clone(),
                    // landed on A
                    ChannelId::new(channels::AB),
                ));
                trace
            },
        };
        let expected_denom = PrefixedDenom {
            base_denom: base_denoms::B.parse().unwrap(),
            trace_path: TracePath::empty(),
        };
        let got_denom = pfm
            .next
            .get_denom_for_this_chain(
                &transfer_port,
                &ChannelId::new(channels::BA),
                &transfer_port,
                &ChannelId::new(channels::AB),
                &source_denom,
            )
            .unwrap();
        assert_eq!(expected_denom, got_denom);
    }
}
