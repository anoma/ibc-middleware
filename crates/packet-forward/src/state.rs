use alloc::vec::Vec;
use core::num::NonZeroU8;

#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};
use ibc_core_channel_types::packet::Packet;
use ibc_core_channel_types::timeout::{TimeoutHeight, TimeoutTimestamp};
use ibc_core_host_types::identifiers::{ChannelId, PortId, Sequence};
use ibc_primitives::Signer;
use serde::{Deserialize, Serialize};

use crate::msg::Duration;

/// [`InFlightPacket`] data to facilitate its storage in a
/// key:value store.
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Hash, Clone)]
pub struct InFlightPacketKey {
    /// Port of the transfer through the current chain.
    pub port: PortId,
    /// Channel of the transfer through the current chain.
    pub channel: ChannelId,
    /// Sequence number of the packet traversing the `port/channel`
    /// pair defined above, through the current chain.
    pub sequence: Sequence,
}

/// Packet that is currently being transmitted to a destination
/// chain over multiple hops.
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone)]
#[cfg_attr(feature = "borsh", derive(BorshDeserialize, BorshSerialize))]
pub struct InFlightPacket {
    /// Sender of the packet on the source chain.
    pub original_sender_address: Signer,
    /// Port where the packet was received in the
    /// current chain.
    pub refund_port_id: PortId,
    /// Channel where the packet was received in the
    /// current chain.
    pub refund_channel_id: ChannelId,
    /// Port on the sending chain.
    pub packet_src_port_id: PortId,
    /// Channel on the sending chain.
    pub packet_src_channel_id: ChannelId,
    /// Timeout timestamp of the original packet.
    pub packet_timeout_timestamp: TimeoutTimestamp,
    /// Timeout height of the original packet.
    pub packet_timeout_height: TimeoutHeight,
    /// Data of the source packet.
    pub packet_data: Vec<u8>,
    /// Sequence number of the source packet.
    pub refund_sequence: Sequence,
    /// Number of retries remaining before the
    /// packet is refunded.
    pub retries_remaining: Option<NonZeroU8>,
    /// Timeout duration, relative to some
    /// instant (usually a block timestamp).
    pub timeout: Duration,
}

impl From<InFlightPacket> for Packet {
    fn from(inflight_packet: InFlightPacket) -> Packet {
        Self {
            seq_on_a: inflight_packet.refund_sequence,
            port_id_on_a: inflight_packet.packet_src_port_id,
            chan_id_on_a: inflight_packet.packet_src_channel_id,
            port_id_on_b: inflight_packet.refund_port_id,
            chan_id_on_b: inflight_packet.refund_channel_id,
            data: inflight_packet.packet_data,
            timeout_height_on_b: inflight_packet.packet_timeout_height,
            timeout_timestamp_on_b: inflight_packet.packet_timeout_timestamp,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg;
    use crate::tests::utils::{channels, get_dummy_coin, get_encoded_dummy_packet_data};

    #[test]
    fn conversion_from_inflight_packet_to_ibc_packet() {
        let inflight_packet = InFlightPacket {
            original_sender_address: String::new().into(),
            refund_port_id: PortId::transfer(),
            refund_channel_id: ChannelId::new(channels::BA),
            packet_src_port_id: PortId::transfer(),
            packet_src_channel_id: ChannelId::new(channels::AB),
            packet_timeout_timestamp: TimeoutTimestamp::Never,
            packet_timeout_height: TimeoutHeight::Never,
            packet_data: get_encoded_dummy_packet_data(get_dummy_coin(100)),
            refund_sequence: 0u64.into(),
            retries_remaining: NonZeroU8::new(1),
            timeout: msg::Duration::from_dur(dur::Duration::from_secs(600)),
        };
        let packet: Packet = inflight_packet.clone().into();

        assert_eq!(inflight_packet.refund_sequence, packet.seq_on_a);

        assert_eq!(inflight_packet.packet_src_port_id, packet.port_id_on_a);
        assert_eq!(inflight_packet.packet_src_channel_id, packet.chan_id_on_a);

        assert_eq!(inflight_packet.refund_port_id, packet.port_id_on_b);
        assert_eq!(inflight_packet.refund_channel_id, packet.chan_id_on_b);

        assert_eq!(inflight_packet.packet_data, packet.data);

        assert_eq!(
            inflight_packet.packet_timeout_height,
            packet.timeout_height_on_b
        );
        assert_eq!(
            inflight_packet.packet_timeout_timestamp,
            packet.timeout_timestamp_on_b
        );
    }
}
