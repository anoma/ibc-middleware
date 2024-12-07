use std::collections::HashSet;

use ibc_app_transfer_types::Amount;
use ibc_testkit::testapp::ibc::applications::transfer::types::DummyTransferModule;

use super::*;

pub mod addresses {
    pub const A: &str = "a1arndt";
    #[allow(dead_code)]
    pub const B: &str = "b1bertha";
    pub const C: &str = "c1copernicus";
    pub const D: &str = "d1dionysus";

    pub const NULL: &str = "NULL";
    pub const RELAYER: &str = "RELAYER";
    pub const ESCROW_ACCOUNT: &str = "b1escrowaccount";
}

pub trait StrExt {
    fn signer(&self) -> Signer;
}

impl StrExt for str {
    fn signer(&self) -> Signer {
        self.to_string().into()
    }
}

// NOTE: Assume we have three chains: A, B, and C. The tests will be set
// up as if we were chain B, forwarding a packet from A to C.
pub mod channels {
    // Outgoing channels from A.
    pub const AB: u64 = 0;

    // Outgoing channels from B.
    pub const BA: u64 = 1;
    pub const BC: u64 = 2;

    // Outgoing channels from C.
    pub const CB: u64 = 3;
    pub const CD: u64 = 4;

    // Outgoing channels from D.
    #[allow(dead_code)]
    pub const DC: u64 = 5;
}

pub mod base_denoms {
    pub const A: &str = "uauauiua";
    pub const B: &str = "ubongus";
    pub const C: &str = "uchungus";
    pub const D: &str = "udongus";
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum FailurePoint {
    BeforeNextMiddlewareOnRecvPacket,
    AfterNextMiddlewareOnRecvPacket,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Ord, PartialOrd, Clone)]
pub struct PacketMetadata {
    pub overflow_receive: OverflowReceiveMetadata,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Ord, PartialOrd, Clone)]
pub struct OverflowReceiveMetadata {
    pub overflow_receiver: Signer,
    pub target_amount: Amount,
}

impl msg::PacketMetadata for PacketMetadata {
    fn is_overflow_receive_msg(msg: &serde_json::Map<String, serde_json::Value>) -> bool {
        msg.contains_key("overflow_receive")
    }

    fn strip_middleware_msg(
        mut json_obj_memo: serde_json::Map<String, serde_json::Value>,
    ) -> serde_json::Map<String, serde_json::Value> {
        json_obj_memo.remove("overflow_receive");
        json_obj_memo
    }

    fn overflow_receiver(&self) -> &Signer {
        &self.overflow_receive.overflow_receiver
    }

    fn target_amount(&self) -> &Amount {
        &self.overflow_receive.target_amount
    }
}

#[derive(Debug)]
pub struct Store<M> {
    middleware: M,
    failure_injections: HashSet<FailurePoint>,
    pub overriden_packets_received: Vec<Packet>,
    pub minted_coins: Vec<(Signer, Coin<PrefixedDenom>)>,
    pub unescrowed_coins: Vec<(PortId, ChannelId, Signer, Coin<PrefixedDenom>)>,
}

impl<M> Store<M> {
    pub fn new(middleware: M) -> Self {
        Self {
            middleware,
            failure_injections: HashSet::new(),
            overriden_packets_received: vec![],
            minted_coins: vec![],
            unescrowed_coins: vec![],
        }
    }

    fn check_failure_injection(&self, point: FailurePoint) -> Result<(), String> {
        if !self.failure_injections.contains(&point) {
            Ok(())
        } else {
            Err(failure_injection_err_msg(point))
        }
    }
}

from_middleware! {
    impl<M> IbcCoreModule for Store<M>
    where
        M: IbcCoreModule,
}

impl<M> MiddlewareModule for Store<M>
where
    M: IbcCoreModule,
{
    type NextMiddleware = M;

    fn next_middleware(&self) -> &M {
        &self.middleware
    }

    fn next_middleware_mut(&mut self) -> &mut M {
        &mut self.middleware
    }

    fn middleware_on_recv_packet_execute(
        &mut self,
        packet: &Packet,
        relayer: &Signer,
    ) -> (ModuleExtras, Option<Acknowledgement>) {
        self.overriden_packets_received.push(packet.clone());

        if let Err(err) =
            self.check_failure_injection(FailurePoint::BeforeNextMiddlewareOnRecvPacket)
        {
            return (
                ModuleExtras::empty(),
                Some(crate::new_error_ack(err).into()),
            );
        }

        let (extras, maybe_ack) = self.middleware.on_recv_packet_execute(packet, relayer);

        if let Err(err) =
            self.check_failure_injection(FailurePoint::AfterNextMiddlewareOnRecvPacket)
        {
            return (
                ModuleExtras::empty(),
                Some(crate::new_error_ack(err).into()),
            );
        }

        (
            extras,
            maybe_ack.map(|ack| {
                if ack.as_bytes() == [1] {
                    Acknowledgement::try_from(br#"{"result": "great success"}"#.to_vec()).unwrap()
                } else {
                    Acknowledgement::try_from(br#"{"error": "oh no"}"#.to_vec()).unwrap()
                }
            }),
        )
    }
}

impl<M> OverflowRecvContext for Store<M> {
    type PacketMetadata = PacketMetadata;
    type Error = String;

    fn mint_coins_validate(
        &self,
        _receiver: &Signer,
        _coin: &Coin<PrefixedDenom>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn mint_coins_execute(
        &mut self,
        receiver: &Signer,
        coin: &Coin<PrefixedDenom>,
    ) -> Result<(), Self::Error> {
        self.minted_coins.push((receiver.clone(), coin.clone()));
        Ok(())
    }

    fn unescrow_coins_validate(
        &self,
        _receiver: &Signer,
        _port: &PortId,
        _channel: &ChannelId,
        _coin: &Coin<PrefixedDenom>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn unescrow_coins_execute(
        &mut self,
        receiver: &Signer,
        port: &PortId,
        channel: &ChannelId,
        coin: &Coin<PrefixedDenom>,
    ) -> Result<(), Self::Error> {
        self.unescrowed_coins.push((
            port.clone(),
            channel.clone(),
            receiver.clone(),
            coin.clone(),
        ));
        Ok(())
    }
}

impl<M> OverflowReceiveMiddleware<Store<M>> {
    pub fn inject_failure(&mut self, point: FailurePoint) {
        self.next.failure_injections.insert(point);
    }
}

#[track_caller]
pub fn assert_failure_injection<T>(point: FailurePoint, result: Result<T, MiddlewareError>) {
    let caller = std::panic::Location::caller();

    let error_msg = match result {
        Ok(_) => {
            panic!(
                "Panicked from {caller} due to failure injection \
                     assertion: Expected {point:?}, but no error was found"
            );
        }
        Err(MiddlewareError::ForwardToNextMiddleware) => {
            panic!(
                "Panicked from {caller} due to failure injection \
                     assertion: Expected {point:?}, but we were trying \
                     to forward a call to the next middleware"
            );
        }
        Err(MiddlewareError::Message(error_msg)) => error_msg,
    };

    let expected_failure_point_err_msg = failure_injection_err_msg(point);
    let Some((_, got_failure_point_err_msg)) = error_msg.rsplit_once(": ") else {
        panic!(
            "Panicked from {caller} due to failure injection \
                 assertion: Expected {point:?} related error, \
                 but got this error instead: {error_msg}"
        );
    };

    if got_failure_point_err_msg != expected_failure_point_err_msg {
        panic!(
            "Panicked from {caller} due to failure injection \
                 assertion: Expected {point:?}, but the error was \
                 different: {error_msg}"
        );
    }
}

fn failure_injection_err_msg(point: FailurePoint) -> String {
    format!("Failure injection on {point:?}")
}

pub type DummyOrm = OverflowReceiveMiddleware<Store<DummyTransferModule>>;

pub fn get_dummy_orm() -> DummyOrm {
    OverflowReceiveMiddleware::wrap(Store::new(DummyTransferModule::new()))
}
