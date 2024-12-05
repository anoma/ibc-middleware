//! IBC module to facilitate middleware implementations.

#![no_std]

use ibc_core_channel_types::acknowledgement::Acknowledgement;
use ibc_core_channel_types::channel::{Counterparty, Order};
use ibc_core_channel_types::error::{ChannelError, PacketError};
use ibc_core_channel_types::packet::Packet;
use ibc_core_channel_types::Version;
use ibc_core_host_types::identifiers::{ChannelId, ConnectionId, PortId};
use ibc_core_router::module::Module;
use ibc_core_router_types::module::ModuleExtras;
use ibc_primitives::Signer;

pub trait MiddlewareModule {
    type NextMiddleware: Module;

    fn next_middleware(&self) -> &Self::NextMiddleware;

    fn next_middleware_mut(&mut self) -> &mut Self::NextMiddleware;

    #[inline(always)]
    fn middleware_on_chan_open_init_validate(
        &self,
        order: Order,
        connection_hops: &[ConnectionId],
        port_id: &PortId,
        channel_id: &ChannelId,
        counterparty: &Counterparty,
        version: &Version,
    ) -> Result<Version, ChannelError> {
        self.next_middleware().on_chan_open_init_validate(
            order,
            connection_hops,
            port_id,
            channel_id,
            counterparty,
            version,
        )
    }

    #[inline(always)]
    fn middleware_on_chan_open_init_execute(
        &mut self,
        order: Order,
        connection_hops: &[ConnectionId],
        port_id: &PortId,
        channel_id: &ChannelId,
        counterparty: &Counterparty,
        version: &Version,
    ) -> Result<(ModuleExtras, Version), ChannelError> {
        self.next_middleware_mut().on_chan_open_init_execute(
            order,
            connection_hops,
            port_id,
            channel_id,
            counterparty,
            version,
        )
    }

    #[inline(always)]
    fn middleware_on_chan_open_try_validate(
        &self,
        order: Order,
        connection_hops: &[ConnectionId],
        port_id: &PortId,
        channel_id: &ChannelId,
        counterparty: &Counterparty,
        counterparty_version: &Version,
    ) -> Result<Version, ChannelError> {
        self.next_middleware().on_chan_open_try_validate(
            order,
            connection_hops,
            port_id,
            channel_id,
            counterparty,
            counterparty_version,
        )
    }

    #[inline(always)]
    fn middleware_on_chan_open_try_execute(
        &mut self,
        order: Order,
        connection_hops: &[ConnectionId],
        port_id: &PortId,
        channel_id: &ChannelId,
        counterparty: &Counterparty,
        counterparty_version: &Version,
    ) -> Result<(ModuleExtras, Version), ChannelError> {
        self.next_middleware_mut().on_chan_open_try_execute(
            order,
            connection_hops,
            port_id,
            channel_id,
            counterparty,
            counterparty_version,
        )
    }

    #[inline(always)]
    fn middleware_on_chan_open_ack_validate(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
        counterparty_version: &Version,
    ) -> Result<(), ChannelError> {
        self.next_middleware()
            .on_chan_open_ack_validate(port_id, channel_id, counterparty_version)
    }

    #[inline(always)]
    fn middleware_on_chan_open_ack_execute(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
        counterparty_version: &Version,
    ) -> Result<ModuleExtras, ChannelError> {
        self.next_middleware_mut().on_chan_open_ack_execute(
            port_id,
            channel_id,
            counterparty_version,
        )
    }

    #[inline(always)]
    fn middleware_on_chan_open_confirm_validate(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<(), ChannelError> {
        self.next_middleware()
            .on_chan_open_confirm_validate(port_id, channel_id)
    }

    #[inline(always)]
    fn middleware_on_chan_open_confirm_execute(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<ModuleExtras, ChannelError> {
        self.next_middleware_mut()
            .on_chan_open_confirm_execute(port_id, channel_id)
    }

    #[inline(always)]
    fn middleware_on_chan_close_init_validate(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<(), ChannelError> {
        self.next_middleware()
            .on_chan_close_init_validate(port_id, channel_id)
    }

    #[inline(always)]
    fn middleware_on_chan_close_init_execute(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<ModuleExtras, ChannelError> {
        self.next_middleware_mut()
            .on_chan_close_init_execute(port_id, channel_id)
    }

    #[inline(always)]
    fn middleware_on_chan_close_confirm_validate(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<(), ChannelError> {
        self.next_middleware()
            .on_chan_close_confirm_validate(port_id, channel_id)
    }

    #[inline(always)]
    fn middleware_on_chan_close_confirm_execute(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<ModuleExtras, ChannelError> {
        self.next_middleware_mut()
            .on_chan_close_confirm_execute(port_id, channel_id)
    }

    #[inline(always)]
    fn middleware_on_recv_packet_execute(
        &mut self,
        packet: &Packet,
        relayer: &Signer,
    ) -> (ModuleExtras, Option<Acknowledgement>) {
        self.next_middleware_mut()
            .on_recv_packet_execute(packet, relayer)
    }

    #[inline(always)]
    fn middleware_on_acknowledgement_packet_validate(
        &self,
        packet: &Packet,
        acknowledgement: &Acknowledgement,
        relayer: &Signer,
    ) -> Result<(), PacketError> {
        self.next_middleware()
            .on_acknowledgement_packet_validate(packet, acknowledgement, relayer)
    }

    #[inline(always)]
    fn middleware_on_acknowledgement_packet_execute(
        &mut self,
        packet: &Packet,
        acknowledgement: &Acknowledgement,
        relayer: &Signer,
    ) -> (ModuleExtras, Result<(), PacketError>) {
        self.next_middleware_mut()
            .on_acknowledgement_packet_execute(packet, acknowledgement, relayer)
    }

    #[inline(always)]
    fn middleware_on_timeout_packet_validate(
        &self,
        packet: &Packet,
        relayer: &Signer,
    ) -> Result<(), PacketError> {
        self.next_middleware()
            .on_timeout_packet_validate(packet, relayer)
    }

    #[inline(always)]
    fn middleware_on_timeout_packet_execute(
        &mut self,
        packet: &Packet,
        relayer: &Signer,
    ) -> (ModuleExtras, Result<(), PacketError>) {
        self.next_middleware_mut()
            .on_timeout_packet_execute(packet, relayer)
    }
}

#[cfg(test)]
mod tests {
    use ibc_middleware_module_macros::ModuleFromMiddleware;
    use ibc_testkit::testapp::ibc::applications::transfer::types::DummyTransferModule;

    use super::*;

    #[derive(Debug, ModuleFromMiddleware)]
    struct DummyMiddleware<M>(M);

    impl<M> MiddlewareModule for DummyMiddleware<M>
    where
        M: Module,
    {
        type NextMiddleware = M;

        fn next_middleware(&self) -> &Self::NextMiddleware {
            &self.0
        }

        fn next_middleware_mut(&mut self) -> &mut Self::NextMiddleware {
            &mut self.0
        }

        fn middleware_on_chan_close_init_validate(
            &self,
            _: &PortId,
            _: &ChannelId,
        ) -> Result<(), ChannelError> {
            panic!("panicked from middleware")
        }
    }

    fn assert_module_impl<M: Module>() {}

    #[test]
    fn dummy_middleware_is_module() {
        assert_module_impl::<DummyMiddleware<DummyTransferModule>>();
    }

    #[test]
    #[should_panic = "panicked from middleware"]
    fn dummy_middleware_overrides_method() {
        _ = DummyMiddleware(DummyTransferModule)
            .on_chan_close_init_validate(&PortId::transfer(), &ChannelId::new(0));
    }
}
