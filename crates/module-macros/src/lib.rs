extern crate proc_macro;

use quote::quote;

#[proc_macro_derive(ModuleFromMiddleware)]
pub fn derive_module_from_middleware(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    derive_module_from_middleware_inner(input.into()).into()
}

fn derive_module_from_middleware_inner(
    input: proc_macro2::TokenStream,
) -> proc_macro2::TokenStream {
    let _struct = syn::parse2::<syn::ItemStruct>(input).expect("Expected struct definition");

    let struct_name = &_struct.ident;
    //let struct_generics = &_struct.generics;

    quote! {
        impl Module for #struct_name {
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
