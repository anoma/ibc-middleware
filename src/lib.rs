//! Core crate defining IBC middleware types and traits.

/// Callbacks that modules must define, as specified in ICS-26.
#[doc(inline)]
pub use ibc_core_router::module::Module as ModuleCallbacks;

#[doc(inline)]
pub use ibc_core_channel_types::packet::Packet;

#[doc(inline)]
pub use ibc_core_channel_types::error::ChannelError;

#[doc(inline)]
pub use ibc_core_channel::context::SendPacketExecutionContext;

#[doc(inline)]
pub use ibc_core_channel::context::SendPacketValidationContext;

/// IBC module callbacks and channel communication methods.
pub trait Middleware:
    ModuleCallbacks + SendPacketExecutionContext + SendPacketValidationContext
{
    /// Execute the send op of an ICS-04 packet.
    fn send_packet_execute(&mut self, packet: Packet) -> Result<(), ChannelError> {
        ibc_core_channel::handler::send_packet_execute(self, packet)
    }

    /// Validate the send op of an ICS-04 packet.
    fn send_packet_validate(&self, packet: Packet) -> Result<(), ChannelError> {
        ibc_core_channel::handler::send_packet_validate(self, packet)
    }
}
