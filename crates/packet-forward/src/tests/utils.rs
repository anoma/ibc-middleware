use std::collections::HashSet;

use ibc_app_transfer_types::{TracePath, TracePrefix};
use ibc_primitives::Timestamp;
use ibc_testkit::testapp::ibc::applications::transfer::types::DummyTransferModule;

use super::*;

pub mod addresses {
    pub const A: &str = "a1arndt";
    #[allow(dead_code)]
    pub const B: &str = "b1bertha";
    pub const C: &str = "c1copernicus";
    #[allow(dead_code)]
    pub const D: &str = "c1dionysus";

    pub const NULL: &str = "NULL";
    pub const ESCROW_ACCOUNT: &str = "b1escrowaccount";
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
    #[allow(dead_code)]
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

impl<M> IbcCoreModule for Store<M>
where
    M: IbcCoreModule,
{
    fn on_recv_packet_execute(
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

    fn on_acknowledgement_packet_validate(
        &self,
        packet: &Packet,
        acknowledgement: &Acknowledgement,
        relayer: &Signer,
    ) -> Result<(), PacketError> {
        self.middleware
            .on_acknowledgement_packet_validate(packet, acknowledgement, relayer)
    }

    fn on_acknowledgement_packet_execute(
        &mut self,
        packet: &Packet,
        acknowledgement: &Acknowledgement,
        relayer: &Signer,
    ) -> (ModuleExtras, Result<(), PacketError>) {
        self.middleware
            .on_acknowledgement_packet_execute(packet, acknowledgement, relayer)
    }

    fn on_timeout_packet_validate(
        &self,
        packet: &Packet,
        relayer: &Signer,
    ) -> Result<(), PacketError> {
        self.middleware.on_timeout_packet_validate(packet, relayer)
    }

    fn on_timeout_packet_execute(
        &mut self,
        packet: &Packet,
        relayer: &Signer,
    ) -> (ModuleExtras, Result<(), PacketError>) {
        self.middleware.on_timeout_packet_execute(packet, relayer)
    }

    fn on_chan_open_init_validate(
        &self,
        order: Order,
        connection_hops: &[ConnectionId],
        port_id: &PortId,
        channel_id: &ChannelId,
        counterparty: &Counterparty,
        version: &Version,
    ) -> Result<Version, ChannelError> {
        self.middleware.on_chan_open_init_validate(
            order,
            connection_hops,
            port_id,
            channel_id,
            counterparty,
            version,
        )
    }

    fn on_chan_open_init_execute(
        &mut self,
        order: Order,
        connection_hops: &[ConnectionId],
        port_id: &PortId,
        channel_id: &ChannelId,
        counterparty: &Counterparty,
        version: &Version,
    ) -> Result<(ModuleExtras, Version), ChannelError> {
        self.middleware.on_chan_open_init_execute(
            order,
            connection_hops,
            port_id,
            channel_id,
            counterparty,
            version,
        )
    }

    fn on_chan_open_try_validate(
        &self,
        order: Order,
        connection_hops: &[ConnectionId],
        port_id: &PortId,
        channel_id: &ChannelId,
        counterparty: &Counterparty,
        counterparty_version: &Version,
    ) -> Result<Version, ChannelError> {
        self.middleware.on_chan_open_try_validate(
            order,
            connection_hops,
            port_id,
            channel_id,
            counterparty,
            counterparty_version,
        )
    }

    fn on_chan_open_try_execute(
        &mut self,
        order: Order,
        connection_hops: &[ConnectionId],
        port_id: &PortId,
        channel_id: &ChannelId,
        counterparty: &Counterparty,
        counterparty_version: &Version,
    ) -> Result<(ModuleExtras, Version), ChannelError> {
        self.middleware.on_chan_open_try_execute(
            order,
            connection_hops,
            port_id,
            channel_id,
            counterparty,
            counterparty_version,
        )
    }

    fn on_chan_open_ack_validate(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
        counterparty_version: &Version,
    ) -> Result<(), ChannelError> {
        self.middleware
            .on_chan_open_ack_validate(port_id, channel_id, counterparty_version)
    }

    fn on_chan_open_ack_execute(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
        counterparty_version: &Version,
    ) -> Result<ModuleExtras, ChannelError> {
        self.middleware
            .on_chan_open_ack_execute(port_id, channel_id, counterparty_version)
    }

    fn on_chan_open_confirm_validate(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<(), ChannelError> {
        self.middleware
            .on_chan_open_confirm_validate(port_id, channel_id)
    }

    fn on_chan_open_confirm_execute(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<ModuleExtras, ChannelError> {
        self.middleware
            .on_chan_open_confirm_execute(port_id, channel_id)
    }

    fn on_chan_close_init_validate(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<(), ChannelError> {
        self.middleware
            .on_chan_close_init_validate(port_id, channel_id)
    }

    fn on_chan_close_init_execute(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<ModuleExtras, ChannelError> {
        self.middleware
            .on_chan_close_init_execute(port_id, channel_id)
    }

    fn on_chan_close_confirm_validate(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<(), ChannelError> {
        self.middleware
            .on_chan_close_confirm_validate(port_id, channel_id)
    }

    fn on_chan_close_confirm_execute(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<ModuleExtras, ChannelError> {
        self.middleware
            .on_chan_close_confirm_execute(port_id, channel_id)
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
        Ok(addresses::ESCROW_ACCOUNT.to_string().into())
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
        Ok(self.inflight_packet_store.get(key).cloned())
    }

    fn delete_inflight_packet(&mut self, key: &InFlightPacketKey) -> Result<(), Self::Error> {
        self.inflight_packet_store.remove(key);
        Ok(())
    }

    fn get_denom_for_this_chain(
        &self,
        this_chain_port: &PortId,
        this_chain_chan: &ChannelId,
        source_port: &PortId,
        source_chan: &ChannelId,
        source_denom: &PrefixedDenom,
    ) -> Result<PrefixedDenom, Self::Error> {
        let transfer_port = PortId::transfer();
        assert_eq!(this_chain_port, &transfer_port);
        assert_eq!(source_port, &transfer_port);

        let this_chain_chan: u64 = this_chain_chan
            .as_str()
            .strip_prefix("channel-")
            .unwrap()
            .parse()
            .unwrap();
        let source_chan: u64 = source_chan
            .as_str()
            .strip_prefix("channel-")
            .unwrap()
            .parse()
            .unwrap();

        assert_eq!((source_chan, this_chain_chan), (channels::AB, channels::BA));

        let trace_prefix = TracePrefix::new(transfer_port.clone(), ChannelId::new(source_chan));

        if source_denom.trace_path.starts_with(&trace_prefix) {
            // NB: we're either dealing with `base_denoms::B`, `base_denoms::C`,
            // or `base_denoms::D`. we must unwrap `source_denom`.

            let this_chain_trace_path = {
                let mut trace = source_denom.trace_path.clone();
                trace.remove_prefix(&trace_prefix);
                trace
            };

            Ok(PrefixedDenom {
                base_denom: source_denom.base_denom.clone(),
                trace_path: this_chain_trace_path,
            })
        } else {
            // NB: this has to be `base_denoms::A`. we must
            // wrap `source_denom`.

            assert!(source_denom.trace_path.is_empty());
            assert_eq!(source_denom.base_denom.as_str(), base_denoms::A);

            Ok(PrefixedDenom {
                base_denom: base_denoms::A.parse().unwrap(),
                trace_path: {
                    let mut trace = TracePath::empty();
                    trace.add_prefix(TracePrefix::new(
                        transfer_port,
                        ChannelId::new(this_chain_chan),
                    ));
                    trace
                },
            })
        }
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

pub fn get_dummy_pfm() -> PacketForwardMiddleware<Store<DummyTransferModule>> {
    PacketForwardMiddleware::next(Store::new(DummyTransferModule::new()))
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
    transfer_amount: u64,
    meta: msg::PacketMetadata,
) -> PacketData {
    get_dummy_packet_data_with_memo(transfer_amount, serde_json::to_string(&meta).unwrap())
}

pub fn get_dummy_packet_data_with_memo(transfer_amount: u64, memo: String) -> PacketData {
    PacketData {
        sender: addresses::A.to_string().into(),
        // NB: the ICS-20 receiver field is overriden
        receiver: addresses::NULL.to_string().into(),
        token: get_dummy_coin(transfer_amount),
        memo: memo.into(),
    }
}

pub fn get_dummy_packet_data(transfer_amount: u64) -> PacketData {
    get_dummy_packet_data_with_memo(transfer_amount, String::new())
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
        receiver: addresses::C.to_string().into(),
        port: PortId::transfer(),
        channel: ChannelId::new(channels::BC),
        timeout: None,
        retries: None,
        next: None,
    }
}

#[test]
fn get_denom_for_this_chain_works_as_expected() {
    let pfm = get_dummy_pfm();

    let transfer_port = PortId::transfer();

    // A => B
    let source_denom = PrefixedDenom {
        base_denom: base_denoms::A.parse().unwrap(),
        trace_path: TracePath::empty(),
    };
    let expected_denom = PrefixedDenom {
        base_denom: base_denoms::A.parse().unwrap(),
        trace_path: {
            let mut trace = TracePath::empty();
            trace.add_prefix(TracePrefix::new(
                transfer_port.clone(),
                // landed on B
                ChannelId::new(channels::BA),
            ));
            trace
        },
    };
    let got_denom = pfm
        .next
        .get_denom_for_this_chain(
            &transfer_port,
            &ChannelId::new(channels::BA),
            &transfer_port,
            &ChannelId::new(channels::AB),
            &source_denom,
        )
        .unwrap();
    assert_eq!(expected_denom, got_denom);

    // C => B => A => B
    let source_denom = PrefixedDenom {
        base_denom: base_denoms::C.parse().unwrap(),
        trace_path: {
            let mut trace = TracePath::empty();
            trace.add_prefix(TracePrefix::new(
                transfer_port.clone(),
                // landed on B
                ChannelId::new(channels::BC),
            ));
            trace.add_prefix(TracePrefix::new(
                transfer_port.clone(),
                // landed on A
                ChannelId::new(channels::AB),
            ));
            trace
        },
    };
    let expected_denom = PrefixedDenom {
        base_denom: base_denoms::C.parse().unwrap(),
        trace_path: {
            let mut trace = TracePath::empty();
            trace.add_prefix(TracePrefix::new(
                transfer_port.clone(),
                // landed on B
                ChannelId::new(channels::BC),
            ));
            trace
        },
    };
    let got_denom = pfm
        .next
        .get_denom_for_this_chain(
            &transfer_port,
            &ChannelId::new(channels::BA),
            &transfer_port,
            &ChannelId::new(channels::AB),
            &source_denom,
        )
        .unwrap();
    assert_eq!(expected_denom, got_denom);

    // B => A => B
    let source_denom = PrefixedDenom {
        base_denom: base_denoms::B.parse().unwrap(),
        trace_path: {
            let mut trace = TracePath::empty();
            trace.add_prefix(TracePrefix::new(
                transfer_port.clone(),
                // landed on A
                ChannelId::new(channels::AB),
            ));
            trace
        },
    };
    let expected_denom = PrefixedDenom {
        base_denom: base_denoms::B.parse().unwrap(),
        trace_path: TracePath::empty(),
    };
    let got_denom = pfm
        .next
        .get_denom_for_this_chain(
            &transfer_port,
            &ChannelId::new(channels::BA),
            &transfer_port,
            &ChannelId::new(channels::AB),
            &source_denom,
        )
        .unwrap();
    assert_eq!(expected_denom, got_denom);

    // D => C => B => A => B
    let source_denom = PrefixedDenom {
        base_denom: base_denoms::D.parse().unwrap(),
        trace_path: {
            let mut trace = TracePath::empty();
            trace.add_prefix(TracePrefix::new(
                transfer_port.clone(),
                // landed on C
                ChannelId::new(channels::CD),
            ));
            trace.add_prefix(TracePrefix::new(
                transfer_port.clone(),
                // landed on B
                ChannelId::new(channels::BC),
            ));
            trace.add_prefix(TracePrefix::new(
                transfer_port.clone(),
                // landed on A
                ChannelId::new(channels::AB),
            ));
            trace
        },
    };
    let expected_denom = PrefixedDenom {
        base_denom: base_denoms::D.parse().unwrap(),
        trace_path: {
            let mut trace = TracePath::empty();
            trace.add_prefix(TracePrefix::new(
                transfer_port.clone(),
                // landed on C
                ChannelId::new(channels::CD),
            ));
            trace.add_prefix(TracePrefix::new(
                transfer_port.clone(),
                // landed on B
                ChannelId::new(channels::BC),
            ));
            trace
        },
    };
    let got_denom = pfm
        .next
        .get_denom_for_this_chain(
            &transfer_port,
            &ChannelId::new(channels::BA),
            &transfer_port,
            &ChannelId::new(channels::AB),
            &source_denom,
        )
        .unwrap();
    assert_eq!(expected_denom, got_denom);
}
