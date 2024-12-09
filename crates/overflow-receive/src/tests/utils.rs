use std::collections::HashSet;

use ibc_app_transfer_types::Amount;
use ibc_core_channel_types::timeout::{TimeoutHeight, TimeoutTimestamp};
use ibc_testkit::testapp::ibc::applications::transfer::types::DummyTransferModule;

use super::*;

pub mod addresses {
    pub const ALFONSO: &str = "ALFONSO";
    pub const BERTHA: &str = "BERTHA";
    pub const CARLOS: &str = "CARLOS";
    pub const RELAYER: &str = "RELAYER";
}

pub const SRC_CHANNEL_ID: u64 = 0;
pub const DST_CHANNEL_ID: u64 = !SRC_CHANNEL_ID;
pub const BASE_DENOM: &str = "uchungus";

pub trait StrExt {
    fn signer(&self) -> Signer;
}

impl StrExt for str {
    fn signer(&self) -> Signer {
        self.to_string().into()
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum FailurePoint {
    MintCoinsExecute,
    BeforeNextMiddlewareOnRecvPacket,
    AfterNextMiddlewareOnRecvPacket,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Ord, PartialOrd, Clone)]
pub struct OrmPacketMetadata {
    pub overflow_receive: OverflowReceiveMetadata,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Ord, PartialOrd, Clone)]
pub struct OverflowReceiveMetadata {
    pub overflow_receiver: Signer,
    pub target_amount: Amount,
}

impl msg::PacketMetadata for OrmPacketMetadata {
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
    pub overflow_minted_coins: Vec<(Signer, Coin<PrefixedDenom>)>,
    pub overflow_unescrowed_coins: Vec<(PortId, ChannelId, Signer, Coin<PrefixedDenom>)>,
}

impl<M> Store<M> {
    pub fn new(middleware: M) -> Self {
        Self {
            middleware,
            failure_injections: HashSet::new(),
            overriden_packets_received: vec![],
            overflow_minted_coins: vec![],
            overflow_unescrowed_coins: vec![],
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
    type PacketMetadata = OrmPacketMetadata;
    type Error = String;

    fn mint_coins_execute(
        &mut self,
        receiver: &Signer,
        coin: &Coin<PrefixedDenom>,
    ) -> Result<(), Self::Error> {
        self.check_failure_injection(FailurePoint::MintCoinsExecute)?;
        self.overflow_minted_coins
            .push((receiver.clone(), coin.clone()));
        Ok(())
    }

    fn unescrow_coins_execute(
        &mut self,
        receiver: &Signer,
        port: &PortId,
        channel: &ChannelId,
        coin: &Coin<PrefixedDenom>,
    ) -> Result<(), Self::Error> {
        self.overflow_unescrowed_coins.push((
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

    pub fn eject_failure(&mut self, point: FailurePoint) {
        self.next.failure_injections.remove(&point);
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

pub fn get_dummy_orm_packet(token: &str, target: u64, received: u64) -> Packet {
    Packet {
        data: serde_json::to_vec(&PacketData {
            sender: addresses::ALFONSO.signer(),
            receiver: addresses::BERTHA.signer(),
            token: Coin {
                denom: token.parse().unwrap(),
                amount: received.into(),
            },
            memo: serde_json::to_string(&get_dummy_orm_metadata(target))
                .unwrap()
                .into(),
        })
        .unwrap(),
        seq_on_a: 0u64.into(),
        port_id_on_a: PortId::transfer(),
        chan_id_on_a: ChannelId::new(SRC_CHANNEL_ID),
        port_id_on_b: PortId::transfer(),
        chan_id_on_b: ChannelId::new(DST_CHANNEL_ID),
        timeout_height_on_b: TimeoutHeight::Never,
        timeout_timestamp_on_b: TimeoutTimestamp::Never,
    }
}

pub fn get_dummy_orm_metadata(target: u64) -> OrmPacketMetadata {
    OrmPacketMetadata {
        overflow_receive: OverflowReceiveMetadata {
            overflow_receiver: addresses::CARLOS.signer(),
            target_amount: target.into(),
        },
    }
}
