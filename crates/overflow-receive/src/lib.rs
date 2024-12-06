//! IBC middleware that sends amounts overflowing some target to another address.

//////////////
// TODO: remove this later
#![allow(dead_code)]
//////////////
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

use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use ibc_app_transfer_types::{Coin, PrefixedDenom};
use ibc_core_channel_types::acknowledgement::{
    Acknowledgement, AcknowledgementStatus, StatusValue as AckStatusValue,
};
use ibc_core_channel_types::channel::{Counterparty, Order};
use ibc_core_channel_types::error::{ChannelError, PacketError};
use ibc_core_channel_types::packet::Packet;
use ibc_core_channel_types::Version;
use ibc_core_host_types::identifiers::{ChannelId, ConnectionId, PortId};
use ibc_core_router::module::Module as IbcCoreModule;
use ibc_core_router_types::event::{ModuleEvent, ModuleEventAttribute};
use ibc_core_router_types::module::ModuleExtras;
use ibc_middleware_module::MiddlewareModule;
use ibc_middleware_module_macros::from_middleware;
use ibc_primitives::*;

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
    /// Error returned by fallible operations.
    type Error: fmt::Display;

    /// Handle receiving some overflow amount. The logic is similar
    /// to `on_recv_packet_execute`, in that tokens need to be
    /// unescrowed or minted.
    fn recv_overflow_execute(
        &mut self,
        receiver: &Signer,
        coin: Coin<PrefixedDenom>,
    ) -> Result<(), Self::Error>;

    /// Handle refunding some overflow amount that had been received.
    /// The logic is similar to `on_timeout_packet_execute`, in that
    /// tokens need to be escrowed or burned.
    fn revert_recv_overflow_execute(
        &mut self,
        receiver: &Signer,
        coin: Coin<PrefixedDenom>,
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
        _packet: &Packet,
        _relayer: &Signer,
    ) -> (ModuleExtras, Option<Acknowledgement>) {
        todo!()
    }

    fn middleware_on_acknowledgement_packet_execute(
        &mut self,
        _packet: &Packet,
        _acknowledgement: &Acknowledgement,
        _relayer: &Signer,
    ) -> (ModuleExtras, Result<(), PacketError>) {
        todo!()
    }

    fn middleware_on_timeout_packet_execute(
        &mut self,
        _packet: &Packet,
        _relayer: &Signer,
    ) -> (ModuleExtras, Result<(), PacketError>) {
        todo!()
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
fn new_packet_error(message: impl fmt::Display) -> Result<(), PacketError> {
    Err(PacketError::Other {
        description: format!("{MODULE} error: {message}"),
    })
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

#[inline]
fn emit_event_with_attrs(extras: &mut ModuleExtras, attributes: Vec<ModuleEventAttribute>) {
    extras.events.push(ModuleEvent {
        kind: MODULE.to_owned(),
        attributes,
    });
}
