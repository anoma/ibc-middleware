use alloc::vec::Vec;
use core::num::NonZeroU8;

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
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Hash, Clone)]
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
    pub retries_remaining: NonZeroU8,
    /// Timeout duration, relative to some
    /// instant (usually a block timestamp).
    pub timeout: Duration,
}
