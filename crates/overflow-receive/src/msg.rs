use ibc_app_transfer_types::Amount;
use ibc_primitives::Signer;
use serde::{Deserialize, Serialize};

/// Metadata included in ICS-20 packet memos.
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Ord, PartialOrd, Clone)]
pub struct PacketMetadata {
    /// Overflow receive middleware metadata.
    pub overflow_receive: OverflowReceiveMetadata,
}

/// Metadata included in ICS-20 packet memos,
/// related with the overflow receive middleware.
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Ord, PartialOrd, Clone)]
pub struct OverflowReceiveMetadata {
    /// Account that shall receive the funds in case of an
    /// overflow.
    pub overflow_receiver: Signer,
    /// The target amount that the original receiver will
    /// receive.
    pub target_amount: Amount,
}
