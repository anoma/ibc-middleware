//! IBC middleware that sends amounts overflowing some target to another address.

#![cfg_attr(not(test), no_std)]
#![cfg_attr(test, deny(clippy::assertions_on_result_states))]
#![cfg_attr(
    not(test),
    deny(
        missing_docs,
        rust_2018_idioms,
        clippy::string_to_string,
        clippy::std_instead_of_core,
        clippy::string_add,
        clippy::str_to_string,
        clippy::infinite_loop,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::cfg_not_test,
        clippy::as_conversions,
        clippy::alloc_instead_of_core,
        clippy::float_arithmetic,
        clippy::empty_docs,
        clippy::empty_line_after_doc_comments,
        clippy::empty_line_after_outer_attr,
        clippy::suspicious_doc_comments,
        clippy::redundant_locals,
        clippy::redundant_comparisons,
        clippy::out_of_bounds_indexing,
        clippy::empty_loop,
        clippy::cast_sign_loss,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_lossless,
        clippy::arithmetic_side_effects,
        clippy::dbg_macro,
        clippy::print_stdout,
        clippy::print_stderr,
        clippy::shadow_unrelated,
        clippy::useless_attribute,
        clippy::zero_repeat_side_effects,
        clippy::builtin_type_shadow,
        clippy::unreachable
    )
)]

extern crate alloc;

mod msg;
#[cfg(test)]
pub(crate) mod tests;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use ibc_app_transfer_types::packet::PacketData;
use ibc_app_transfer_types::{is_receiver_chain_source, Coin, PrefixedDenom, TracePrefix};
use ibc_core_channel_types::acknowledgement::{
    Acknowledgement, AcknowledgementStatus, StatusValue as AckStatusValue,
};
use ibc_core_channel_types::channel::{Counterparty, Order};
use ibc_core_channel_types::error::{ChannelError, PacketError};
use ibc_core_channel_types::packet::Packet;
use ibc_core_channel_types::Version;
use ibc_core_host_types::identifiers::{ChannelId, ConnectionId, PortId};
use ibc_core_router::module::Module as IbcCoreModule;
use ibc_core_router_types::event::ModuleEventAttribute;
use ibc_core_router_types::module::ModuleExtras;
use ibc_middleware_module::MiddlewareModule;
use ibc_middleware_module_macros::from_middleware;
use ibc_primitives::*;
use serde::{Deserialize, Serialize};

#[doc(inline)]
pub use self::msg::PacketMetadata;

/// Module name of the ORM.
const MODULE: &str = "overflow-receive-middleware";

#[derive(Debug)]
enum MiddlewareError {
    /// Error message.
    Message(String),
    /// Forward the call to the next middleware.
    ForwardToNextMiddleware,
}

/// Context data required by the [`OverflowReceiveMiddleware`].
pub trait OverflowRecvContext {
    /// Metadata included in ICS-20 packet memos,
    /// related with the overflow receive middleware.
    type PacketMetadata: msg::PacketMetadata + Serialize + for<'de> Deserialize<'de> + Sized;

    /// Error returned by fallible operations.
    type Error: fmt::Display;

    /// Validate the minting of coins.
    fn mint_coins_validate(
        &self,
        receiver: &Signer,
        coin: &Coin<PrefixedDenom>,
    ) -> Result<(), Self::Error>;

    /// Mint coins.
    fn mint_coins_execute(
        &mut self,
        receiver: &Signer,
        coin: &Coin<PrefixedDenom>,
    ) -> Result<(), Self::Error>;

    /// Validate the unescrowing of coins.
    fn unescrow_coins_validate(
        &self,
        receiver: &Signer,
        port: &PortId,
        channel: &ChannelId,
        coin: &Coin<PrefixedDenom>,
    ) -> Result<(), Self::Error>;

    /// Unescrow coins.
    fn unescrow_coins_execute(
        &mut self,
        receiver: &Signer,
        port: &PortId,
        channel: &ChannelId,
        coin: &Coin<PrefixedDenom>,
    ) -> Result<(), Self::Error>;
}

/// Overflow receive middleware entrypoint, which intercepts compatible
/// ICS-20 packets and sends funds to a new address in case they exceed
/// some specified amount.
#[derive(Debug)]
pub struct OverflowReceiveMiddleware<M> {
    next: M,
}

impl<M> OverflowReceiveMiddleware<M> {
    /// Return an immutable ref to the next middleware.
    pub fn next(&self) -> &M {
        &self.next
    }

    /// Return a mutable ref to the next middleware.
    pub fn next_mut(&mut self) -> &mut M {
        &mut self.next
    }

    /// Wrap an existing middleware in the ORM.
    pub const fn wrap(next: M) -> Self {
        Self { next }
    }
}

from_middleware! {
    impl<M> IbcCoreModule for OverflowReceiveMiddleware<M>
    where
        M: IbcCoreModule + OverflowRecvContext,
}

impl<M> OverflowReceiveMiddleware<M>
where
    M: IbcCoreModule + OverflowRecvContext,
{
    fn on_recv_packet_execute_inner(
        &mut self,
        extras: &mut ModuleExtras,
        packet: &Packet,
        relayer: &Signer,
    ) -> Result<Option<Acknowledgement>, MiddlewareError> {
        let (transfer_pkt, orm_metadata) =
            decode_overflow_receive_msg::<M::PacketMetadata>(packet)?;

        let (override_amount, remainder_amount) = match transfer_pkt
            .token
            .amount
            .checked_sub(*orm_metadata.target_amount())
        {
            Some(amt) if *amt != [0u64, 0, 0, 0] => (*orm_metadata.target_amount(), amt),
            _ => return Err(MiddlewareError::ForwardToNextMiddleware),
        };

        let mut attributes = vec![];

        if is_receiver_chain_source(
            packet.port_id_on_a.clone(),
            packet.chan_id_on_a.clone(),
            &transfer_pkt.token.denom,
        ) {
            let prefix = TracePrefix::new(packet.port_id_on_a.clone(), packet.chan_id_on_a.clone());
            let coin = {
                let mut c = transfer_pkt.token.clone();
                c.denom.remove_trace_prefix(&prefix);
                c
            };

            self.next
                .unescrow_coins_validate(
                    orm_metadata.overflow_receiver(),
                    &packet.port_id_on_b,
                    &packet.chan_id_on_b,
                    &coin,
                )
                .map_err(|err| {
                    MiddlewareError::Message(format!(
                        "Validation of unescrow to {} failed: {err}",
                        orm_metadata.overflow_receiver()
                    ))
                })?;
            self.next
                .unescrow_coins_execute(
                    orm_metadata.overflow_receiver(),
                    &packet.port_id_on_b,
                    &packet.chan_id_on_b,
                    &coin,
                )
                .map_err(|err| {
                    MiddlewareError::Message(format!(
                        "Unescrow to {} failed: {err}",
                        orm_metadata.overflow_receiver()
                    ))
                })?;

            push_event_attr(&mut attributes, "operation", "unescrow");
        } else {
            let prefix = TracePrefix::new(packet.port_id_on_b.clone(), packet.chan_id_on_b.clone());
            let coin = {
                let mut c = transfer_pkt.token.clone();
                c.denom.add_trace_prefix(prefix);
                c
            };

            self.next
                .mint_coins_validate(orm_metadata.overflow_receiver(), &coin)
                .map_err(|err| {
                    MiddlewareError::Message(format!(
                        "Validation of mint to {} failed: {err}",
                        orm_metadata.overflow_receiver()
                    ))
                })?;
            self.next
                .mint_coins_execute(orm_metadata.overflow_receiver(), &coin)
                .map_err(|err| {
                    MiddlewareError::Message(format!(
                        "Mint to {} failed: {err}",
                        orm_metadata.overflow_receiver()
                    ))
                })?;
        }

        push_event_attr(
            &mut attributes,
            "info",
            format!(
                "Redirecting {remainder_amount}{} to {}",
                transfer_pkt.token.denom,
                orm_metadata.overflow_receiver()
            ),
        );

        let override_packet = {
            let ics20_packet_data = PacketData {
                token: Coin {
                    denom: transfer_pkt.token.denom.clone(),
                    amount: override_amount,
                },
                memo: extract_next_memo_from_orm_packet::<M::PacketMetadata>(&transfer_pkt).into(),
                ..transfer_pkt
            };

            let encoded_packet_data = serde_json::to_vec(&ics20_packet_data).map_err(|err| {
                MiddlewareError::Message(format!("Failed to encode ICS-20 packet: {err}"))
            })?;

            Packet {
                data: encoded_packet_data,
                ..packet.clone()
            }
        };
        let (next_extras, maybe_ack) = self.next.on_recv_packet_execute(&override_packet, relayer);
        join_module_extras(extras, next_extras);

        Ok(maybe_ack)
    }
}

impl<M> MiddlewareModule for OverflowReceiveMiddleware<M>
where
    M: IbcCoreModule + OverflowRecvContext,
{
    type NextMiddleware = M;

    #[inline]
    fn next_middleware(&self) -> &M {
        self.next()
    }

    #[inline]
    fn next_middleware_mut(&mut self) -> &mut M {
        self.next_mut()
    }

    fn middleware_on_recv_packet_execute(
        &mut self,
        packet: &Packet,
        relayer: &Signer,
    ) -> (ModuleExtras, Option<Acknowledgement>) {
        let mut extras = ModuleExtras::empty();

        match self.on_recv_packet_execute_inner(&mut extras, packet, relayer) {
            Ok(maybe_ack) => (extras, maybe_ack),
            Err(MiddlewareError::ForwardToNextMiddleware) => {
                self.next.on_recv_packet_execute(packet, relayer)
            }
            Err(MiddlewareError::Message(err)) => (extras, Some(new_error_ack(err).into())),
        }
    }
}

#[inline]
fn new_error_ack(message: impl fmt::Display) -> AcknowledgementStatus {
    AcknowledgementStatus::error(
        // NB: allow expect here, because this should only fail if
        // we construct an `AckStatusValue` with an empty message
        #[allow(clippy::expect_used)]
        AckStatusValue::new(format!("{MODULE} error: {message}"))
            .expect("Acknowledgement error must not be empty"),
    )
}

#[inline]
fn event_attr<K, V>(key: K, value: V) -> ModuleEventAttribute
where
    K: Into<String>,
    V: Into<String>,
{
    ModuleEventAttribute {
        key: key.into(),
        value: value.into(),
    }
}

#[inline]
fn push_event_attr<K, V>(attributes: &mut Vec<ModuleEventAttribute>, key: K, value: V)
where
    K: Into<String>,
    V: Into<String>,
{
    attributes.push(event_attr(key, value));
}

fn decode_ics20_msg(packet: &Packet) -> Result<PacketData, MiddlewareError> {
    serde_json::from_slice(&packet.data).map_err(|_| {
        // NB: if `packet.data` is not a valid fungible token transfer
        // packet, we forward the call to the next middleware
        MiddlewareError::ForwardToNextMiddleware
    })
}

fn decode_overflow_receive_msg<Msg>(packet: &Packet) -> Result<(PacketData, Msg), MiddlewareError>
where
    Msg: msg::PacketMetadata + for<'de> Deserialize<'de>,
{
    let transfer_pkt = decode_ics20_msg(packet)?;

    let json_obj_memo: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(transfer_pkt.memo.as_ref()).map_err(|_| {
            // NB: if the ICS-20 packet memo is not a valid JSON object, we forward
            // this call to the next middleware
            MiddlewareError::ForwardToNextMiddleware
        })?;

    if !Msg::is_overflow_receive_msg(&json_obj_memo) {
        // NB: the memo was a valid json object, but it wasn't up to
        // the ORM to consume it, so we forward the call to the next middleware
        return Err(MiddlewareError::ForwardToNextMiddleware);
    }

    serde_json::from_value(json_obj_memo.into()).map_or_else(
        |err| Err(MiddlewareError::Message(err.to_string())),
        |msg| Ok((transfer_pkt, msg)),
    )
}

fn join_module_extras(first: &mut ModuleExtras, mut second: ModuleExtras) {
    first.events.append(&mut second.events);
    first.log.append(&mut second.log);
}

// NB: Assume that `src_packet_data` has been validated as a PFM packet
#[inline]
fn extract_next_memo_from_orm_packet<Msg>(src_packet_data: &PacketData) -> String
where
    Msg: PacketMetadata,
{
    #[allow(clippy::unwrap_used, clippy::unreachable)]
    let serde_json::Value::Object(memo_obj) =
        serde_json::from_str(src_packet_data.memo.as_ref()).unwrap()
    else {
        unreachable!()
    };

    #[allow(clippy::unwrap_used)]
    serde_json::to_string(&Msg::strip_middleware_msg(memo_obj)).unwrap()
}
