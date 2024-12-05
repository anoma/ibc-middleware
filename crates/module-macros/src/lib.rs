extern crate proc_macro;

use quote::quote;

/// Generate an IBC module from a type that implements
/// an IBC middleware module.
///
/// ## Example
///
/// ```ignore
/// from_middleware! {
///     impl<M> Module for Middleware<M>
///     where
///         M: Module,
/// }
/// ```
#[proc_macro]
pub fn from_middleware(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    from_middleware_inner(input.into()).into()
}

fn from_middleware_inner(
    impl_def_up_to_block: proc_macro2::TokenStream,
) -> proc_macro2::TokenStream {
    quote! {
        #impl_def_up_to_block
        {
            #[inline(always)]
            fn on_chan_open_init_validate(
                &self,
                order: Order,
                connection_hops: &[ConnectionId],
                port_id: &PortId,
                channel_id: &ChannelId,
                counterparty: &Counterparty,
                version: &Version,
            ) -> Result<Version, ChannelError> {
                self.middleware_on_chan_open_init_validate(
                    order,
                    connection_hops,
                    port_id,
                    channel_id,
                    counterparty,
                    version,
                )
            }

            #[inline(always)]
            fn on_chan_open_init_execute(
                &mut self,
                order: Order,
                connection_hops: &[ConnectionId],
                port_id: &PortId,
                channel_id: &ChannelId,
                counterparty: &Counterparty,
                version: &Version,
            ) -> Result<(ModuleExtras, Version), ChannelError> {
                self.middleware_on_chan_open_init_execute(
                    order,
                    connection_hops,
                    port_id,
                    channel_id,
                    counterparty,
                    version,
                )
            }

            #[inline(always)]
            fn on_chan_open_try_validate(
                &self,
                order: Order,
                connection_hops: &[ConnectionId],
                port_id: &PortId,
                channel_id: &ChannelId,
                counterparty: &Counterparty,
                counterparty_version: &Version,
            ) -> Result<Version, ChannelError> {
                self.middleware_on_chan_open_try_validate(
                    order,
                    connection_hops,
                    port_id,
                    channel_id,
                    counterparty,
                    counterparty_version,
                )
            }

            #[inline(always)]
            fn on_chan_open_try_execute(
                &mut self,
                order: Order,
                connection_hops: &[ConnectionId],
                port_id: &PortId,
                channel_id: &ChannelId,
                counterparty: &Counterparty,
                counterparty_version: &Version,
            ) -> Result<(ModuleExtras, Version), ChannelError> {
                self.middleware_on_chan_open_try_execute(
                    order,
                    connection_hops,
                    port_id,
                    channel_id,
                    counterparty,
                    counterparty_version,
                )
            }

            #[inline(always)]
            fn on_chan_open_ack_validate(
                &self,
                port_id: &PortId,
                channel_id: &ChannelId,
                counterparty_version: &Version,
            ) -> Result<(), ChannelError> {
                self.middleware_on_chan_open_ack_validate(port_id, channel_id, counterparty_version)
            }

            #[inline(always)]
            fn on_chan_open_ack_execute(
                &mut self,
                port_id: &PortId,
                channel_id: &ChannelId,
                counterparty_version: &Version,
            ) -> Result<ModuleExtras, ChannelError> {
                self.middleware_on_chan_open_ack_execute(port_id, channel_id, counterparty_version)
            }

            #[inline(always)]
            fn on_chan_open_confirm_validate(
                &self,
                port_id: &PortId,
                channel_id: &ChannelId,
            ) -> Result<(), ChannelError> {
                self.middleware_on_chan_open_confirm_validate(port_id, channel_id)
            }

            #[inline(always)]
            fn on_chan_open_confirm_execute(
                &mut self,
                port_id: &PortId,
                channel_id: &ChannelId,
            ) -> Result<ModuleExtras, ChannelError> {
                self.middleware_on_chan_open_confirm_execute(port_id, channel_id)
            }

            #[inline(always)]
            fn on_chan_close_init_validate(
                &self,
                port_id: &PortId,
                channel_id: &ChannelId,
            ) -> Result<(), ChannelError> {
                self.middleware_on_chan_close_init_validate(port_id, channel_id)
            }

            #[inline(always)]
            fn on_chan_close_init_execute(
                &mut self,
                port_id: &PortId,
                channel_id: &ChannelId,
            ) -> Result<ModuleExtras, ChannelError> {
                self.middleware_on_chan_close_init_execute(port_id, channel_id)
            }

            #[inline(always)]
            fn on_chan_close_confirm_validate(
                &self,
                port_id: &PortId,
                channel_id: &ChannelId,
            ) -> Result<(), ChannelError> {
                self.middleware_on_chan_close_confirm_validate(port_id, channel_id)
            }

            #[inline(always)]
            fn on_chan_close_confirm_execute(
                &mut self,
                port_id: &PortId,
                channel_id: &ChannelId,
            ) -> Result<ModuleExtras, ChannelError> {
                self.middleware_on_chan_close_confirm_execute(port_id, channel_id)
            }

            #[inline(always)]
            fn on_recv_packet_execute(
                &mut self,
                packet: &Packet,
                relayer: &Signer,
            ) -> (ModuleExtras, Option<Acknowledgement>) {
                self.middleware_on_recv_packet_execute(packet, relayer)
            }

            #[inline(always)]
            fn on_acknowledgement_packet_validate(
                &self,
                packet: &Packet,
                acknowledgement: &Acknowledgement,
                relayer: &Signer,
            ) -> Result<(), PacketError> {
                self.middleware_on_acknowledgement_packet_validate(packet, acknowledgement, relayer)
            }

            #[inline(always)]
            fn on_acknowledgement_packet_execute(
                &mut self,
                packet: &Packet,
                acknowledgement: &Acknowledgement,
                relayer: &Signer,
            ) -> (ModuleExtras, Result<(), PacketError>) {
                self.middleware_on_acknowledgement_packet_execute(packet, acknowledgement, relayer)
            }

            #[inline(always)]
            fn on_timeout_packet_validate(
                &self,
                packet: &Packet,
                relayer: &Signer,
            ) -> Result<(), PacketError> {
                self.middleware_on_timeout_packet_validate(packet, relayer)
            }

            #[inline(always)]
            fn on_timeout_packet_execute(
                &mut self,
                packet: &Packet,
                relayer: &Signer,
            ) -> (ModuleExtras, Result<(), PacketError>) {
                self.middleware_on_timeout_packet_execute(packet, relayer)
            }
        }
    }
}
