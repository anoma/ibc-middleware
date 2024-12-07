use alloc::string::String;

use ibc_app_transfer_types::Amount;
use ibc_primitives::Signer;

/// Metadata included in ICS-20 packet memos,
/// related with the overflow receive middleware.
pub trait PacketMetadata {
    /// Determine if the value `msg` is a valid `PacketMetadata`.
    fn is_overflow_receive_msg(msg: &serde_json::Map<String, serde_json::Value>) -> bool;

    /// Remove this middleware's entry from the JSON object memo.
    fn strip_middleware_msg(
        json_obj_memo: serde_json::Map<String, serde_json::Value>,
    ) -> serde_json::Map<String, serde_json::Value>;

    /// Account that shall receive the funds in case of an
    /// overflow.
    fn overflow_receiver(&self) -> &Signer;

    /// The target amount that the original receiver will
    /// receive.
    fn target_amount(&self) -> &Amount;
}
