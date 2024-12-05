use std::collections::HashSet;

use ibc_primitives::Timestamp;
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
    BeforeSendTransfer,
    AfterSendTransfer,
    BeforeNextMiddlewareOnRecvPacket,
    AfterNextMiddlewareOnRecvPacket,
    BeforeStoreInFlightPacket,
    AfterStoreInFlightPacket,
    RetrieveInFlightPacket,
}

#[derive(Debug)]
pub struct Store<M> {
    middleware: M,
    failure_injections: HashSet<FailurePoint>,
    pub inflight_packet_store: HashMap<InFlightPacketKey, InFlightPacket>,
    pub sent_transfers: Vec<MsgTransfer>,
    pub refunds_received: Vec<(Packet, PacketData)>,
    pub refunds_sent: Vec<InFlightPacket>,
    pub ack_and_events_written: Vec<(Packet, Acknowledgement)>,
}

impl<M> Store<M> {
    pub fn new(middleware: M) -> Self {
        Self {
            middleware,
            inflight_packet_store: HashMap::new(),
            sent_transfers: Vec::new(),
            refunds_received: Vec::new(),
            refunds_sent: Vec::new(),
            ack_and_events_written: Vec::new(),
            failure_injections: HashSet::new(),
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

impl<M> PfmContext for Store<M> {
    type Error = String;

    fn send_transfer_execute(&mut self, msg: MsgTransfer) -> Result<Sequence, Self::Error> {
        self.check_failure_injection(FailurePoint::BeforeSendTransfer)?;
        let seq = Sequence::from(self.sent_transfers.len() as u64);
        self.sent_transfers.push(msg);
        self.check_failure_injection(FailurePoint::AfterSendTransfer)?;
        Ok(seq)
    }

    fn receive_refund_execute(
        &mut self,
        packet: &Packet,
        transfer_pkt: PacketData,
    ) -> Result<(), Self::Error> {
        self.refunds_received.push((packet.clone(), transfer_pkt));
        Ok(())
    }

    fn send_refund_execute(&mut self, inflight_packet: &InFlightPacket) -> Result<(), Self::Error> {
        self.refunds_sent.push(inflight_packet.clone());
        Ok(())
    }

    fn write_ack_and_events(
        &mut self,
        packet: &Packet,
        acknowledgement: &Acknowledgement,
    ) -> Result<(), Self::Error> {
        self.ack_and_events_written
            .push((packet.clone(), acknowledgement.clone()));
        Ok(())
    }

    fn override_receiver(
        &self,
        _channel: &ChannelId,
        _original_sender: &Signer,
    ) -> Result<Signer, Self::Error> {
        Ok(addresses::ESCROW_ACCOUNT.signer())
    }

    fn timeout_timestamp(
        &self,
        timeout_duration: dur::Duration,
    ) -> Result<TimeoutTimestamp, Self::Error> {
        let nanos: u64 = timeout_duration.as_nanos().try_into().map_err(|e| {
            format!("Could not convert duration {timeout_duration} to u64 nanos: {e}")
        })?;

        Ok(TimeoutTimestamp::At(Timestamp::from_nanoseconds(nanos)))
    }

    fn store_inflight_packet(
        &mut self,
        key: InFlightPacketKey,
        inflight_packet: InFlightPacket,
    ) -> Result<(), Self::Error> {
        self.check_failure_injection(FailurePoint::BeforeStoreInFlightPacket)?;
        self.inflight_packet_store.insert(key, inflight_packet);
        self.check_failure_injection(FailurePoint::AfterStoreInFlightPacket)?;
        Ok(())
    }

    fn retrieve_inflight_packet(
        &self,
        key: &InFlightPacketKey,
    ) -> Result<Option<InFlightPacket>, Self::Error> {
        self.check_failure_injection(FailurePoint::RetrieveInFlightPacket)?;
        Ok(self.inflight_packet_store.get(key).cloned())
    }

    fn delete_inflight_packet(&mut self, key: &InFlightPacketKey) -> Result<(), Self::Error> {
        self.inflight_packet_store.remove(key);
        Ok(())
    }
}

impl<M> PacketForwardMiddleware<Store<M>> {
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

pub type DummyPfm = PacketForwardMiddleware<Store<DummyTransferModule>>;

pub fn get_dummy_pfm() -> DummyPfm {
    PacketForwardMiddleware::wrap(Store::new(DummyTransferModule::new()))
}

pub fn get_dummy_coin(amount: u64) -> Coin<PrefixedDenom> {
    let chan_id = channels::AB;
    let denom = base_denoms::B;

    Coin {
        denom: format!("transfer/channel-{chan_id}/{denom}")
            .parse()
            .unwrap(),
        amount: amount.into(),
    }
}

pub fn get_dummy_packet_data_with_fwd_meta(
    transfer_coin: Coin<PrefixedDenom>,
    meta: msg::PacketMetadata,
) -> PacketData {
    get_dummy_packet_data_with_memo(transfer_coin, serde_json::to_string(&meta).unwrap())
}

pub fn get_dummy_packet_data_with_memo(
    transfer_coin: Coin<PrefixedDenom>,
    memo: String,
) -> PacketData {
    PacketData {
        sender: addresses::A.signer(),
        // NB: the ICS-20 receiver field is overriden
        receiver: addresses::NULL.signer(),
        token: transfer_coin,
        memo: memo.into(),
    }
}

pub fn get_encoded_dummy_packet_data(transfer_coin: Coin<PrefixedDenom>) -> Vec<u8> {
    serde_json::to_vec(&get_dummy_packet_data_with_memo(
        transfer_coin,
        String::new(),
    ))
    .unwrap()
}

pub fn get_dummy_packet_data(transfer_coin: Coin<PrefixedDenom>) -> PacketData {
    get_dummy_packet_data_with_memo(transfer_coin, String::new())
}

pub fn get_dummy_packet_with_data(seq: u64, packet_data: &PacketData) -> Packet {
    Packet {
        data: serde_json::to_vec(packet_data).unwrap(),
        seq_on_a: seq.into(),
        port_id_on_a: PortId::transfer(),
        chan_id_on_a: ChannelId::new(channels::AB),
        port_id_on_b: PortId::transfer(),
        chan_id_on_b: ChannelId::new(channels::BA),
        timeout_height_on_b: TimeoutHeight::Never,
        timeout_timestamp_on_b: TimeoutTimestamp::Never,
    }
}

pub fn get_dummy_fwd_metadata() -> msg::ForwardMetadata {
    msg::ForwardMetadata {
        receiver: addresses::C.signer(),
        port: PortId::transfer(),
        channel: ChannelId::new(channels::BC),
        timeout: None,
        retries: None,
        next: None,
    }
}
