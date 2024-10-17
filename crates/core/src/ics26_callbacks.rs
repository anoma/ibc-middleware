//! ICS-26 module callbacks.

use ibc_core_router::module::Module as IbcCoreModule;

use crate::store::Store;

/// Module callbacks, as specified in ICS-26.
pub trait Module: IbcCoreModule {
    /// Return a reference to the [`Store`].
    fn store(&self) -> &dyn Store;

    /// Return a mutable reference to the [`Store`].
    fn store_mut(&mut self) -> &mut dyn Store;

    /// Upcast to a [core IBC module](IbcCoreModule).
    fn upcast_to_core(&self) -> &dyn IbcCoreModule;

    /// Upcast (mutably) to a [core IBC module](IbcCoreModule).
    fn upcast_to_core_mut(&mut self) -> &mut dyn IbcCoreModule;
}

#[cfg(test)]
mod test_module_upcasting {
    use ibc_core_channel_types::acknowledgement::Acknowledgement;
    use ibc_core_channel_types::channel::{Counterparty, Order};
    use ibc_core_channel_types::error::{ChannelError, PacketError};
    use ibc_core_channel_types::packet::Packet;
    use ibc_core_channel_types::Version;
    use ibc_core_host_types::identifiers::{ChannelId, ConnectionId, PortId};
    use ibc_core_router_types::module::ModuleExtras;
    use ibc_primitives::prelude::*;
    use ibc_primitives::Signer;

    use super::*;
    use crate::test_utils::MockStore;

    #[derive(Debug)]
    struct MockModule {
        store: MockStore,
    }

    impl Module for MockModule {
        fn store(&self) -> &dyn Store {
            &self.store
        }

        fn store_mut(&mut self) -> &mut dyn Store {
            &mut self.store
        }

        fn upcast_to_core(&self) -> &dyn IbcCoreModule {
            let this: &dyn IbcCoreModule = self;

            // NOTE: use methods from `IbcCoreModule` here, to test
            // the circular dependency on `Module` and `IbcCoreModule`
            {
                let port_id = PortId::new("transfer".into()).unwrap();
                let channel_id = ChannelId::new(0);
                assert!(this
                    .on_chan_open_confirm_validate(&port_id, &channel_id)
                    .is_ok());
            }

            this
        }

        fn upcast_to_core_mut(&mut self) -> &mut dyn IbcCoreModule {
            self
        }
    }

    impl IbcCoreModule for MockModule {
        fn on_chan_open_init_validate(
            &self,
            _: Order,
            _: &[ConnectionId],
            _: &PortId,
            _: &ChannelId,
            _: &Counterparty,
            _: &Version,
        ) -> Result<Version, ChannelError> {
            unimplemented!()
        }

        fn on_chan_open_init_execute(
            &mut self,
            _: Order,
            _: &[ConnectionId],
            _: &PortId,
            _: &ChannelId,
            _: &Counterparty,
            _: &Version,
        ) -> Result<(ModuleExtras, Version), ChannelError> {
            // NOTE: use methods from `Module` here, to test
            // the circular dependency on `Module` and `IbcCoreModule`
            _ = self.store();
            _ = self.store_mut();
            _ = self.upcast_to_core();
            _ = self.upcast_to_core_mut();

            unimplemented!()
        }

        fn on_chan_open_try_validate(
            &self,
            _: Order,
            _: &[ConnectionId],
            _: &PortId,
            _: &ChannelId,
            _: &Counterparty,
            _: &Version,
        ) -> Result<Version, ChannelError> {
            unimplemented!()
        }

        fn on_chan_open_try_execute(
            &mut self,
            _: Order,
            _: &[ConnectionId],
            _: &PortId,
            _: &ChannelId,
            _: &Counterparty,
            _: &Version,
        ) -> Result<(ModuleExtras, Version), ChannelError> {
            unimplemented!()
        }

        fn on_chan_open_ack_validate(
            &self,
            _: &PortId,
            _: &ChannelId,
            _: &Version,
        ) -> Result<(), ChannelError> {
            unimplemented!()
        }

        fn on_chan_open_ack_execute(
            &mut self,
            _: &PortId,
            _: &ChannelId,
            _: &Version,
        ) -> Result<ModuleExtras, ChannelError> {
            unimplemented!()
        }

        fn on_chan_open_confirm_validate(
            &self,
            _: &PortId,
            _: &ChannelId,
        ) -> Result<(), ChannelError> {
            Ok(())
        }

        fn on_chan_open_confirm_execute(
            &mut self,
            _: &PortId,
            _: &ChannelId,
        ) -> Result<ModuleExtras, ChannelError> {
            panic!("UPCAST WORKED")
        }

        fn on_chan_close_init_validate(
            &self,
            _: &PortId,
            _: &ChannelId,
        ) -> Result<(), ChannelError> {
            unimplemented!()
        }

        fn on_chan_close_init_execute(
            &mut self,
            _: &PortId,
            _: &ChannelId,
        ) -> Result<ModuleExtras, ChannelError> {
            unimplemented!()
        }

        fn on_chan_close_confirm_validate(
            &self,
            _: &PortId,
            _: &ChannelId,
        ) -> Result<(), ChannelError> {
            unimplemented!()
        }

        fn on_chan_close_confirm_execute(
            &mut self,
            _: &PortId,
            _: &ChannelId,
        ) -> Result<ModuleExtras, ChannelError> {
            unimplemented!()
        }

        fn on_recv_packet_execute(
            &mut self,
            _: &Packet,
            _: &Signer,
        ) -> (ModuleExtras, Acknowledgement) {
            unimplemented!()
        }

        fn on_acknowledgement_packet_validate(
            &self,
            _: &Packet,
            _: &Acknowledgement,
            _: &Signer,
        ) -> Result<(), PacketError> {
            unimplemented!()
        }

        fn on_acknowledgement_packet_execute(
            &mut self,
            _: &Packet,
            _: &Acknowledgement,
            _: &Signer,
        ) -> (ModuleExtras, Result<(), PacketError>) {
            unimplemented!()
        }

        fn on_timeout_packet_validate(&self, _: &Packet, _: &Signer) -> Result<(), PacketError> {
            unimplemented!()
        }

        fn on_timeout_packet_execute(
            &mut self,
            _: &Packet,
            _: &Signer,
        ) -> (ModuleExtras, Result<(), PacketError>) {
            unimplemented!()
        }
    }

    #[test]
    #[should_panic = "UPCAST WORKED"]
    fn upcasting() {
        let mut mock_module = MockModule {
            store: MockStore::default(),
        };

        mock_module.store_mut().write("one", &[1]).unwrap();
        mock_module.store_mut().write("two", &[2]).unwrap();

        assert_eq!(mock_module.store().read("one").unwrap(), vec![1]);
        assert_eq!(mock_module.store().read("two").unwrap(), vec![2]);

        let port_id = PortId::new("transfer".into()).unwrap();
        let channel_id = ChannelId::new(0);

        _ = mock_module.upcast_to_core();

        _ = mock_module
            .upcast_to_core_mut()
            .on_chan_open_confirm_execute(&port_id, &channel_id);
    }
}
