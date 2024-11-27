pub(crate) mod utils;

use std::collections::HashMap;

use ibc_app_transfer_types::{TracePath, TracePrefix};
use ibc_testkit::fixtures::core::channel::dummy_raw_packet;

use self::utils::*;
use super::*;
use crate::new_error_ack;

#[test]
fn decode_ics20_msg_forwards_to_next_middleware() {
    // NB: this packet doesn't have ICS-20 packet data
    let packet: Packet = dummy_raw_packet(0, 1).try_into().unwrap();
    assert!(matches!(
        decode_ics20_msg(&packet),
        Err(MiddlewareError::ForwardToNextMiddleware)
    ));
}

#[test]
fn decode_ics20_msg_on_valid_ics20_data() {
    let expected_packet_data = get_dummy_packet_data(get_dummy_coin(100));
    let packet = get_dummy_packet_with_data(0, &expected_packet_data);

    let got_packet_data = decode_ics20_msg(&packet).unwrap();
    assert_eq!(got_packet_data, expected_packet_data);
}

#[test]
fn decode_forward_msg_forwards_to_next_middleware_not_json() {
    let packet_data = get_dummy_packet_data_with_memo(get_dummy_coin(100), "oh hi mark".to_owned());
    let packet = get_dummy_packet_with_data(0, &packet_data);

    assert!(matches!(
        decode_forward_msg(&packet),
        Err(MiddlewareError::ForwardToNextMiddleware)
    ));
}

#[test]
fn decode_forward_msg_forwards_to_next_middleware_not_pfm_msg() {
    let packet_data =
        get_dummy_packet_data_with_memo(get_dummy_coin(100), r#"{"combo": "breaker"}"#.to_owned());
    let packet = get_dummy_packet_with_data(0, &packet_data);

    assert!(matches!(
        decode_forward_msg(&packet),
        Err(MiddlewareError::ForwardToNextMiddleware)
    ));
}

#[test]
fn decode_forward_msg_failure() {
    let packet_data = get_dummy_packet_data_with_memo(
        get_dummy_coin(100),
        r#"{"forward": {"foot": "best"}}"#.to_owned(),
    );
    let packet = get_dummy_packet_with_data(0, &packet_data);

    assert!(matches!(
        decode_forward_msg(&packet),
        Err(MiddlewareError::Message(_))
    ));
}

#[test]
fn decode_forward_msg_success() {
    let expected_fwd_metadata = msg::PacketMetadata {
        forward: get_dummy_fwd_metadata(),
    };
    let expected_packet_data = get_dummy_packet_data_with_memo(
        get_dummy_coin(100),
        serde_json::to_string(&expected_fwd_metadata).unwrap(),
    );

    let packet = get_dummy_packet_with_data(0, &expected_packet_data);
    let (got_packet_data, got_fwd_metadata) = decode_forward_msg(&packet).unwrap();

    assert_eq!(expected_packet_data, got_packet_data);
    assert_eq!(expected_fwd_metadata.forward, got_fwd_metadata);
}

#[test]
fn next_inflight_packet_decreases_retries() {
    let retries = NonZeroU8::new(2).unwrap();

    let first_inflight_packet = InFlightPacket {
        original_sender_address: String::new().into(),
        refund_port_id: PortId::transfer(),
        refund_channel_id: ChannelId::new(channels::BA),
        packet_src_port_id: PortId::transfer(),
        packet_src_channel_id: ChannelId::new(channels::AB),
        packet_timeout_timestamp: TimeoutTimestamp::Never,
        packet_timeout_height: TimeoutHeight::Never,
        packet_data: get_encoded_dummy_packet_data(get_dummy_coin(100)),
        refund_sequence: 0u64.into(),
        retries_remaining: Some(retries),
        timeout: msg::Duration::from_dur(DEFAULT_FORWARD_TIMEOUT),
    };

    let mut second_inflight_packet = next_inflight_packet(Right(first_inflight_packet.clone()));

    second_inflight_packet.retries_remaining = second_inflight_packet
        .retries_remaining
        .as_mut()
        .unwrap()
        .checked_add(1);

    assert_eq!(first_inflight_packet, second_inflight_packet);
}

#[test]
fn next_inflight_packet_from_packet() {
    let packet_data = get_dummy_packet_data(get_dummy_coin(100));
    let packet = Packet {
        data: serde_json::to_vec(&packet_data).unwrap(),
        port_id_on_b: PortId::transfer(),
        chan_id_on_b: ChannelId::new(channels::BA),
        port_id_on_a: PortId::transfer(),
        chan_id_on_a: ChannelId::new(channels::AB),
        timeout_height_on_b: TimeoutHeight::Never,
        timeout_timestamp_on_b: TimeoutTimestamp::Never,
        seq_on_a: 0u64.into(),
    };

    let got_inflight_packet = next_inflight_packet(Left(NewInFlightPacket {
        src_packet: &packet,
        original_sender: String::new().into(),
        retries: DEFAULT_FORWARD_RETRIES,
        timeout: DEFAULT_FORWARD_TIMEOUT,
    }));

    let expected_inflight_packet = InFlightPacket {
        original_sender_address: String::new().into(),
        refund_port_id: PortId::transfer(),
        refund_channel_id: ChannelId::new(channels::BA),
        packet_src_port_id: PortId::transfer(),
        packet_src_channel_id: ChannelId::new(channels::AB),
        packet_timeout_timestamp: TimeoutTimestamp::Never,
        packet_timeout_height: TimeoutHeight::Never,
        packet_data: get_encoded_dummy_packet_data(get_dummy_coin(100)),
        refund_sequence: 0u64.into(),
        retries_remaining: Some(DEFAULT_FORWARD_RETRIES),
        timeout: msg::Duration::from_dur(DEFAULT_FORWARD_TIMEOUT),
    };

    assert_eq!(got_inflight_packet, expected_inflight_packet);
}

#[test]
fn module_extras_appending() {
    let mut first_extras = ModuleExtras::empty();
    let mut second_extras = ModuleExtras::empty();

    emit_event_with_attrs(&mut first_extras, {
        let mut attributes = Vec::with_capacity(8);
        push_event_attr(&mut attributes, "1".to_owned(), String::new());
        attributes
    });
    emit_event_with_attrs(&mut second_extras, {
        let mut attributes = Vec::with_capacity(8);
        push_event_attr(&mut attributes, "2".to_owned(), String::new());
        attributes
    });

    let extras = {
        join_module_extras(&mut first_extras, second_extras);
        first_extras
    };

    assert!(extras.log.is_empty());
    assert_eq!(
        extras
            .events
            .iter()
            .flat_map(|e| e.attributes.iter().map(|at| &at.key))
            .collect::<Vec<_>>(),
        ["1", "2"]
    );
}

#[test]
fn events_kept_on_errors() {
    let mut pfm = get_dummy_pfm();
    pfm.inject_failure(FailurePoint::BeforeSendTransfer);

    let mut extras = ModuleExtras::empty();

    let packet_data = get_dummy_packet_data(get_dummy_coin(100));
    let packet = get_dummy_packet_with_data(0, &packet_data);
    let fwd_metadata = get_dummy_fwd_metadata();

    let denom_on_this_chain = pfm
        .next
        .get_denom_for_this_chain(
            &packet.port_id_on_b,
            &packet.chan_id_on_b,
            &packet.port_id_on_a,
            &packet.chan_id_on_a,
            &packet_data.token.denom,
        )
        .unwrap();
    let coin_on_this_chain = Coin {
        denom: denom_on_this_chain,
        amount: packet_data.token.amount,
    };

    let expected_extras = {
        let mut ex = ModuleExtras::empty();
        emit_event_with_attrs(&mut ex, {
            let mut attributes = Vec::with_capacity(8);
            push_event_attr(&mut attributes, "is-retry".to_owned(), false.to_string());
            push_event_attr(
                &mut attributes,
                "escrow-account".to_owned(),
                addresses::ESCROW_ACCOUNT.to_string(),
            );
            push_event_attr(
                &mut attributes,
                "sender".to_owned(),
                addresses::A.to_string(),
            );
            push_event_attr(
                &mut attributes,
                "receiver".to_owned(),
                fwd_metadata.receiver.to_string(),
            );
            push_event_attr(
                &mut attributes,
                "port".to_owned(),
                fwd_metadata.port.to_string(),
            );
            push_event_attr(
                &mut attributes,
                "channel".to_owned(),
                fwd_metadata.channel.to_string(),
            );
            attributes
        });
        ex
    };

    assert_failure_injection(
        FailurePoint::BeforeSendTransfer,
        pfm.forward_transfer_packet(
            &mut extras,
            Left(&packet),
            fwd_metadata,
            addresses::A.signer(),
            addresses::ESCROW_ACCOUNT.signer(),
            coin_on_this_chain,
        ),
    );

    assert_eq!(extras.log, expected_extras.log);
    assert_eq!(extras.events, expected_extras.events);
}

fn on_recv_packet_execute_inner(
    pfm: &mut DummyPfm,
    transfer_coin: Coin<PrefixedDenom>,
) -> Result<(), crate::MiddlewareError> {
    let mut extras = ModuleExtras::empty();

    let packet_data = get_dummy_packet_data_with_fwd_meta(
        transfer_coin.clone(),
        msg::PacketMetadata {
            forward: get_dummy_fwd_metadata(),
        },
    );
    let packet = get_dummy_packet_with_data(pfm.next.sent_transfers.len() as u64, &packet_data);

    let coin_on_this_chain = Coin {
        amount: transfer_coin.amount,
        denom: pfm
            .next
            .get_denom_for_this_chain(
                &packet.port_id_on_b,
                &packet.chan_id_on_b,
                &packet.port_id_on_a,
                &packet.chan_id_on_a,
                &packet_data.token.denom,
            )
            .unwrap(),
    };

    pfm.on_recv_packet_execute_inner(&mut extras, &packet, &addresses::RELAYER.signer())?;

    let expected_extras = {
        let mut ex = ModuleExtras::empty();
        emit_event_with_attrs(
            &mut ex,
            vec![
                event_attr("is-retry", "false"),
                event_attr("escrow-account", addresses::ESCROW_ACCOUNT),
                event_attr("sender", addresses::A),
                event_attr("receiver", addresses::C),
                event_attr("port", "transfer"),
                event_attr("channel", ChannelId::new(channels::BC).to_string()),
            ],
        );
        emit_event_with_attrs(
            &mut ex,
            vec![event_attr("info", "Packet has been successfully forwarded")],
        );
        ex
    };
    assert_eq!(extras.log, expected_extras.log);
    assert_eq!(extras.events, expected_extras.events);

    assert!(pfm.next.refunds_received.is_empty());
    assert!(pfm.next.refunds_sent.is_empty());
    assert!(pfm.next.ack_and_events_written.is_empty());

    assert_eq!(
        pfm.next.inflight_packet_store,
        HashMap::from_iter([(
            InFlightPacketKey {
                port: PortId::transfer(),
                channel: ChannelId::new(channels::BC),
                sequence: 0u64.into(),
            },
            InFlightPacket {
                original_sender_address: addresses::A.signer(),
                refund_port_id: PortId::transfer(),
                refund_channel_id: ChannelId::new(channels::BA),
                packet_src_port_id: PortId::transfer(),
                packet_src_channel_id: ChannelId::new(channels::AB),
                packet_timeout_timestamp: TimeoutTimestamp::Never,
                packet_timeout_height: TimeoutHeight::Never,
                refund_sequence: 0u64.into(),
                retries_remaining: Some(DEFAULT_FORWARD_RETRIES),
                timeout: msg::Duration::from_dur(DEFAULT_FORWARD_TIMEOUT),
                packet_data: serde_json::to_vec(&packet_data).unwrap(),
            },
        )])
    );

    assert_eq!(
        pfm.next.sent_transfers,
        vec![MsgTransfer {
            port_id_on_a: PortId::transfer(),
            chan_id_on_a: ChannelId::new(channels::BC),
            timeout_height_on_b: TimeoutHeight::Never,
            timeout_timestamp_on_b: pfm.next.timeout_timestamp(DEFAULT_FORWARD_TIMEOUT).unwrap(),
            packet_data: PacketData {
                sender: addresses::ESCROW_ACCOUNT.signer(),
                receiver: addresses::C.signer(),
                token: coin_on_this_chain,
                memo: String::new().into(),
            },
        }]
    );

    Ok(())
}

fn reconstruct_forwarded_packet(pfm: &DummyPfm) -> Packet {
    let last_seq_no_u64 = pfm.next.sent_transfers.len() as u64 - 1;
    let last_seq_no = Sequence::from(last_seq_no_u64);
    let last_sent_transfer = pfm.next.sent_transfers.last().unwrap();

    Packet {
        data: serde_json::to_vec(&last_sent_transfer.packet_data).unwrap(),
        seq_on_a: last_seq_no,
        port_id_on_a: PortId::transfer(),
        chan_id_on_a: ChannelId::new(channels::BC),
        port_id_on_b: PortId::transfer(),
        chan_id_on_b: ChannelId::new(channels::CB),
        timeout_height_on_b: last_sent_transfer.timeout_height_on_b,
        timeout_timestamp_on_b: last_sent_transfer.timeout_timestamp_on_b,
    }
}

// NB: assume we called `on_recv_packet_execute_inner` prior
// to this call
fn on_acknowledgement_packet_execute_inner(
    pfm: &mut DummyPfm,
    transfer_coin: Coin<PrefixedDenom>,
    ack_from_c: &Acknowledgement,
    extra_assertions: impl FnOnce(InFlightPacket, &mut DummyPfm),
) -> Result<(), crate::MiddlewareError> {
    let mut extras = ModuleExtras::empty();

    let last_seq_no_u64 = pfm.next.sent_transfers.len() as u64 - 1;
    let last_seq_no = Sequence::from(last_seq_no_u64);
    let last_sent_transfer = pfm.next.sent_transfers.last().unwrap();

    assert_eq!(last_sent_transfer.port_id_on_a, PortId::transfer());
    assert_eq!(
        last_sent_transfer.chan_id_on_a,
        ChannelId::new(channels::BC)
    );

    // reconstruct the initial packet:
    //
    // A => B => C
    // [ fwd ]
    //
    let packet_a_b = {
        let packet_data = get_dummy_packet_data_with_fwd_meta(
            transfer_coin,
            msg::PacketMetadata {
                forward: get_dummy_fwd_metadata(),
            },
        );
        get_dummy_packet_with_data(0, &packet_data)
    };

    // reconstruct the forwarded packet:
    //
    // A => B => C
    //     [ fwd ]
    //
    let packet_b_c = reconstruct_forwarded_packet(pfm);

    let inflight_packet_key = InFlightPacketKey {
        port: PortId::transfer(),
        channel: ChannelId::new(channels::BC),
        sequence: last_seq_no,
    };

    let Some(inflight_packet) = pfm
        .next
        .inflight_packet_store
        .get(&inflight_packet_key)
        .cloned()
    else {
        panic!("In-flight packet should have been stored");
    };

    assert!(pfm.next.refunds_received.is_empty());
    assert!(pfm.next.refunds_sent.is_empty());

    pfm.on_acknowledgement_packet_execute_inner(&mut extras, &packet_b_c, ack_from_c)?;

    let (got_packet, got_ack) = pfm.next.ack_and_events_written.last().unwrap();

    assert_eq!(got_packet, &packet_a_b);
    assert_eq!(got_ack, ack_from_c);

    assert!(!pfm
        .next
        .inflight_packet_store
        .contains_key(&inflight_packet_key));

    extra_assertions(inflight_packet, pfm);

    Ok(())
}

fn all_denoms() -> Vec<PrefixedDenom> {
    let transfer_port = PortId::transfer();

    vec![
        // A => B
        PrefixedDenom {
            base_denom: base_denoms::A.parse().unwrap(),
            trace_path: TracePath::empty(),
        },
        // C => B => A => B
        PrefixedDenom {
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
        },
        // B => A => B
        PrefixedDenom {
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
        },
        // D => C => B => A => B
        PrefixedDenom {
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
                    transfer_port,
                    // landed on A
                    ChannelId::new(channels::AB),
                ));
                trace
            },
        },
    ]
}

fn no_timeout_packet_flow_inner(
    ack_from_c: &Acknowledgement,
    mut assertions_after_ack_exec: impl FnMut(InFlightPacket, &mut DummyPfm),
) -> Result<(), crate::MiddlewareError> {
    const TRANSFER_AMOUNT: u64 = 100;

    for denom in all_denoms() {
        let mut pfm = get_dummy_pfm();
        let coin = Coin {
            denom,
            amount: TRANSFER_AMOUNT.into(),
        };

        on_recv_packet_execute_inner(&mut pfm, coin.clone())?;

        on_acknowledgement_packet_execute_inner(
            &mut pfm,
            coin,
            ack_from_c,
            &mut assertions_after_ack_exec,
        )?;
    }

    Ok(())
}

#[test]
fn happy_flow_from_a_to_c() -> Result<(), crate::MiddlewareError> {
    let ack_from_c =
        AcknowledgementStatus::success(AckStatusValue::new("Ack from chain C").unwrap()).into();
    no_timeout_packet_flow_inner(&ack_from_c, |_, pfm| {
        assert!(pfm.next.refunds_received.is_empty());
        assert!(pfm.next.refunds_sent.is_empty());
    })
}

#[test]
fn ack_error_from_a_to_c() -> Result<(), crate::MiddlewareError> {
    let ack_from_c =
        AcknowledgementStatus::error(AckStatusValue::new("Ack err from chain C").unwrap()).into();
    no_timeout_packet_flow_inner(&ack_from_c, |refund_inflight_packet, pfm| {
        let last_seq_no_u64 = pfm.next.sent_transfers.len() as u64 - 1;
        let last_seq_no = Sequence::from(last_seq_no_u64);
        let last_sent_transfer = pfm.next.sent_transfers.last().unwrap();

        let packet_b_c = Packet {
            data: serde_json::to_vec(&last_sent_transfer.packet_data).unwrap(),
            seq_on_a: last_seq_no,
            port_id_on_a: PortId::transfer(),
            chan_id_on_a: ChannelId::new(channels::BC),
            port_id_on_b: PortId::transfer(),
            chan_id_on_b: ChannelId::new(channels::CB),
            timeout_height_on_b: last_sent_transfer.timeout_height_on_b,
            timeout_timestamp_on_b: last_sent_transfer.timeout_timestamp_on_b,
        };

        assert_eq!(
            pfm.next.refunds_received,
            vec![(packet_b_c, last_sent_transfer.packet_data.clone())]
        );
        assert_eq!(pfm.next.refunds_sent, vec![refund_inflight_packet]);
    })
}

#[test]
fn no_state_changes_if_next_fails_on_b() {
    let mut pfm = get_dummy_pfm();
    pfm.inject_failure(FailurePoint::AfterNextMiddlewareOnRecvPacket);

    let mut extras = ModuleExtras::empty();

    let packet_data = get_dummy_packet_data_with_fwd_meta(
        get_dummy_coin(100),
        msg::PacketMetadata {
            forward: get_dummy_fwd_metadata(),
        },
    );
    let packet = get_dummy_packet_with_data(0, &packet_data);

    assert_failure_injection(
        FailurePoint::AfterNextMiddlewareOnRecvPacket,
        pfm.on_recv_packet_execute_inner(&mut extras, &packet, &addresses::RELAYER.signer()),
    );

    assert!(pfm.next.inflight_packet_store.is_empty());
    assert!(pfm.next.sent_transfers.is_empty());
    assert!(pfm.next.refunds_received.is_empty());
    assert!(pfm.next.refunds_sent.is_empty());
    assert!(pfm.next.ack_and_events_written.is_empty());
}

#[test]
fn non_existent_inflight_packet_not_handled_by_pfm() {
    let packet_data = get_dummy_packet_data_with_fwd_meta(
        get_dummy_coin(100),
        msg::PacketMetadata {
            forward: get_dummy_fwd_metadata(),
        },
    );
    let packet = get_dummy_packet_with_data(0, &packet_data);

    // first, check that we fail exactly where we intend to
    // (after checking that we have an ICS-20 packet)
    let mut pfm = get_dummy_pfm();
    pfm.inject_failure(FailurePoint::RetrieveInFlightPacket);
    assert_failure_injection(
        FailurePoint::RetrieveInFlightPacket,
        pfm.on_acknowledgement_packet_execute_inner(
            &mut ModuleExtras::empty(),
            &packet,
            &new_error_ack("RIP").into(),
        ),
    );

    //========

    let mut pfm = get_dummy_pfm();
    assert!(matches!(
        pfm.on_acknowledgement_packet_execute_inner(
            &mut ModuleExtras::empty(),
            &packet,
            &new_error_ack("RIP").into(),
        ),
        Err(MiddlewareError::ForwardToNextMiddleware)
    ));
}

#[test]
fn no_retry_if_not_pfm_packet() {
    let pfm = get_dummy_pfm();

    assert!(pfm.next.inflight_packet_store.is_empty());

    let packet_data = get_dummy_packet_data(get_dummy_coin(100));
    let packet = get_dummy_packet_with_data(0, &packet_data);

    assert!(matches!(
        pfm.timeout_should_retry(&packet),
        Err(MiddlewareError::ForwardToNextMiddleware)
    ));
}

#[test]
fn retry_until_exhausted() {
    let mut pfm = get_dummy_pfm();

    let packet_data = get_dummy_packet_data(get_dummy_coin(100));
    let packet = get_dummy_packet_with_data(0, &packet_data);

    let inflight_packet_key = InFlightPacketKey {
        port: packet.port_id_on_a.clone(),
        channel: packet.chan_id_on_a.clone(),
        sequence: packet.seq_on_a,
    };
    let mut inflight_packet = InFlightPacket {
        original_sender_address: String::new().into(),
        refund_port_id: PortId::transfer(),
        refund_channel_id: packet.chan_id_on_b.clone(),
        packet_src_port_id: PortId::transfer(),
        packet_src_channel_id: packet.chan_id_on_a.clone(),
        packet_timeout_timestamp: packet.timeout_timestamp_on_b,
        packet_timeout_height: packet.timeout_height_on_b,
        refund_sequence: packet.seq_on_a,
        retries_remaining: NonZeroU8::new(1),
        timeout: msg::Duration::from_dur(DEFAULT_FORWARD_TIMEOUT),
        packet_data: serde_json::to_vec(&packet_data).unwrap(),
    };

    pfm.next
        .inflight_packet_store
        .insert(inflight_packet_key.clone(), inflight_packet.clone());

    assert!(matches!(
        pfm.timeout_should_retry(&packet),
        Ok((RetryOutcome::GoAhead, pkt)) if pkt == inflight_packet
    ));

    inflight_packet.retries_remaining = None;
    pfm.next
        .inflight_packet_store
        .insert(inflight_packet_key, inflight_packet.clone());

    assert!(matches!(
        pfm.timeout_should_retry(&packet),
        Ok((RetryOutcome::MaxRetriesExceeded, pkt)) if pkt == inflight_packet
    ));
}

fn on_timeout_packet_execute_inner(
    pfm: &mut DummyPfm,
    transfer_coin: Coin<PrefixedDenom>,
) -> Result<bool, crate::MiddlewareError> {
    let mut extras = ModuleExtras::empty();

    let packet_b_c = reconstruct_forwarded_packet(pfm);

    let timed_out_inflight = {
        assert_eq!(pfm.next.inflight_packet_store.len(), 1);
        let inflight_packet = pfm.next.inflight_packet_store.values().next().unwrap();
        if inflight_packet.retries_remaining.is_none() {
            Some(inflight_packet.clone())
        } else {
            None
        }
    };

    pfm.on_timeout_packet_execute_inner(&mut extras, &packet_b_c, &addresses::RELAYER.signer())?;

    if let Some(timed_out_inflight) = timed_out_inflight {
        assert!(pfm.next.inflight_packet_store.is_empty());
        assert_eq!(pfm.next.sent_transfers.len(), 1);

        let packet_a_b = {
            let packet_data = get_dummy_packet_data_with_fwd_meta(
                transfer_coin,
                msg::PacketMetadata {
                    forward: get_dummy_fwd_metadata(),
                },
            );
            get_dummy_packet_with_data(0, &packet_data)
        };
        let refund_sequence = 0;
        let refund_port_id = PortId::transfer();
        let refund_channel_id = ChannelId::new(channels::BA);
        let expected_ack = new_error_ack(format!(
            "In-flight packet max retries exceeded, for packet with sequence \
             {refund_sequence} on {refund_port_id}/{refund_channel_id}"
        ))
        .into();
        assert_eq!(
            pfm.next.ack_and_events_written,
            vec![(packet_a_b, expected_ack)]
        );

        let packet_b_c = reconstruct_forwarded_packet(pfm);
        let packet_data: PacketData = serde_json::from_slice(&packet_b_c.data).unwrap();
        assert_eq!(pfm.next.refunds_received, vec![(packet_b_c, packet_data)]);
        assert_eq!(pfm.next.refunds_sent, vec![timed_out_inflight]);

        return Ok(false);
    }

    let expected_extras = {
        let mut ex = ModuleExtras::empty();
        emit_event_with_attrs(
            &mut ex,
            vec![
                event_attr("is-retry", "true"),
                event_attr("escrow-account", addresses::ESCROW_ACCOUNT),
                event_attr("sender", addresses::A),
                event_attr("receiver", addresses::C),
                event_attr("port", "transfer"),
                event_attr("channel", ChannelId::new(channels::BC).to_string()),
            ],
        );
        emit_event_with_attrs(
            &mut ex,
            vec![event_attr("info", "Packet has been successfully forwarded")],
        );
        ex
    };
    assert_eq!(extras.log, expected_extras.log);
    assert_eq!(extras.events, expected_extras.events);

    assert_eq!(pfm.next.sent_transfers.len(), 2);
    assert!(pfm
        .next
        .sent_transfers
        .iter()
        .reduce(|t1, t2| {
            if t1 != t2 {
                panic!("All transfers should have been equal");
            }
            t1
        })
        .is_some());

    assert!(pfm.next.refunds_received.is_empty());
    assert!(pfm.next.refunds_sent.is_empty());
    assert!(pfm.next.ack_and_events_written.is_empty());

    let packet_data = get_dummy_packet_data_with_fwd_meta(
        transfer_coin,
        msg::PacketMetadata {
            forward: get_dummy_fwd_metadata(),
        },
    );
    assert_eq!(
        pfm.next.inflight_packet_store,
        HashMap::from_iter([(
            InFlightPacketKey {
                port: PortId::transfer(),
                channel: ChannelId::new(channels::BC),
                sequence: 1u64.into(),
            },
            InFlightPacket {
                original_sender_address: addresses::A.signer(),
                refund_port_id: PortId::transfer(),
                refund_channel_id: ChannelId::new(channels::BA),
                packet_src_port_id: PortId::transfer(),
                packet_src_channel_id: ChannelId::new(channels::AB),
                packet_timeout_timestamp: TimeoutTimestamp::Never,
                packet_timeout_height: TimeoutHeight::Never,
                refund_sequence: 0u64.into(),
                retries_remaining: None,
                timeout: msg::Duration::from_dur(DEFAULT_FORWARD_TIMEOUT),
                packet_data: serde_json::to_vec(&packet_data).unwrap(),
            },
        )])
    );

    Ok(true)
}

fn timeout_packet_flow_inner(has_retries_left: bool) -> Result<(), crate::MiddlewareError> {
    const TRANSFER_AMOUNT: u64 = 100;

    for denom in all_denoms() {
        let mut pfm = get_dummy_pfm();
        let coin = Coin {
            denom,
            amount: TRANSFER_AMOUNT.into(),
        };

        on_recv_packet_execute_inner(&mut pfm, coin.clone())?;

        if !has_retries_left {
            let inflight_packet = pfm.next.inflight_packet_store.values_mut().next().unwrap();
            inflight_packet.retries_remaining = None;
        }

        let packet_went_through = on_timeout_packet_execute_inner(&mut pfm, coin.clone())?;
        assert_eq!(packet_went_through, has_retries_left);

        if packet_went_through {
            let ack_from_c =
                AcknowledgementStatus::success(AckStatusValue::new("Ack from chain C").unwrap())
                    .into();
            on_acknowledgement_packet_execute_inner(&mut pfm, coin, &ack_from_c, |_, pfm| {
                assert!(pfm.next.refunds_received.is_empty());
                assert!(pfm.next.refunds_sent.is_empty());
            })?;
        }
    }

    Ok(())
}

#[test]
fn happy_flow_timeout_retry_from_a_to_c() -> Result<(), crate::MiddlewareError> {
    timeout_packet_flow_inner(true)
}

#[test]
fn max_retries_exceeded_timeout_retry_from_a_to_c() -> Result<(), crate::MiddlewareError> {
    timeout_packet_flow_inner(false)
}

// TODO: retry fwd on timeout until we succeed,
// and check that inflight packet store is empty
// at the end

// TODO: test forwarding from chain A to D. the next memo
// should be filled in with PFM instructions for chain C
// to forward to D
