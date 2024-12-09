pub(crate) mod utils;

use ibc_testkit::fixtures::core::channel::dummy_raw_packet;

use self::utils::*;
use super::*;

#[test]
fn happy_flow_mint() -> Result<(), crate::MiddlewareError> {
    const TARGET: u64 = 100;
    const RECEIVED: u64 = 150;

    let mut orm = get_dummy_orm();

    let mut extras = ModuleExtras::empty();
    let packet = get_dummy_orm_packet(BASE_DENOM, TARGET, RECEIVED);

    orm.on_recv_packet_execute_inner(&mut extras, &packet, &addresses::RELAYER.signer())?;

    assert!(orm.next.overflow_unescrowed_coins.is_empty());
    assert_eq!(
        orm.next.overflow_minted_coins,
        vec![(
            addresses::CARLOS.signer(),
            Coin {
                amount: (RECEIVED - TARGET).into(),
                denom: format!("transfer/channel-{DST_CHANNEL_ID}/{BASE_DENOM}")
                    .parse()
                    .unwrap(),
            },
        )]
    );

    let packet_data = {
        let original: PacketData = serde_json::from_slice(&packet.data).unwrap();
        let token = Coin {
            amount: TARGET.into(),
            denom: original.token.denom.clone(),
        };
        PacketData {
            token,
            memo: "{}".to_string().into(),
            ..original
        }
    };

    assert_eq!(
        orm.next.overriden_packets_received,
        vec![Packet {
            data: serde_json::to_vec(&packet_data).unwrap(),
            ..packet
        }]
    );

    Ok(())
}

#[test]
fn happy_flow_unescrow() -> Result<(), crate::MiddlewareError> {
    const TARGET: u64 = 100;
    const RECEIVED: u64 = 150;

    let mut orm = get_dummy_orm();

    let mut extras = ModuleExtras::empty();
    let packet = get_dummy_orm_packet(
        &format!("transfer/channel-{SRC_CHANNEL_ID}/{BASE_DENOM}"),
        TARGET,
        RECEIVED,
    );

    orm.on_recv_packet_execute_inner(&mut extras, &packet, &addresses::RELAYER.signer())?;

    assert!(orm.next.overflow_minted_coins.is_empty());
    assert_eq!(
        orm.next.overflow_unescrowed_coins,
        vec![(
            PortId::transfer(),
            ChannelId::new(DST_CHANNEL_ID),
            addresses::CARLOS.signer(),
            Coin {
                amount: (RECEIVED - TARGET).into(),
                denom: BASE_DENOM.parse().unwrap(),
            },
        )]
    );

    let packet_data = {
        let original: PacketData = serde_json::from_slice(&packet.data).unwrap();
        let token = Coin {
            amount: TARGET.into(),
            denom: original.token.denom.clone(),
        };
        PacketData {
            token,
            memo: "{}".to_string().into(),
            ..original
        }
    };

    assert_eq!(
        orm.next.overriden_packets_received,
        vec![Packet {
            data: serde_json::to_vec(&packet_data).unwrap(),
            ..packet
        }]
    );

    Ok(())
}

#[test]
fn forward_to_next_middleware_if_zero() {
    const TARGET: u64 = 150;
    const RECEIVED: u64 = 150;

    let packet = get_dummy_orm_packet(BASE_DENOM, TARGET, RECEIVED);

    // NB: narrow down the location of the `ForwardToNextMiddleware`
    // failure to the error originating from `RECEIVED - TARGET`
    // resulting in a null value
    {
        // NB: this shouldn't fail because we have a valid ORM packet
        assert!(crate::decode_overflow_receive_msg::<OrmPacketMetadata>(&packet).is_ok());

        // NB: this should fail because we bail out
        // upon finding that `TARGET == RECEIVED`
        assert!(std::panic::catch_unwind(|| {
            let mut orm = get_dummy_orm();
            orm.inject_failure(FailurePoint::MintCoinsExecute);

            assert_failure_injection(
                FailurePoint::MintCoinsExecute,
                orm.on_recv_packet_execute_inner(
                    &mut ModuleExtras::empty(),
                    &packet,
                    &addresses::RELAYER.signer(),
                ),
            );
        })
        .is_err());
    }

    let mut orm = get_dummy_orm();

    assert!(matches!(
        orm.on_recv_packet_execute_inner(
            &mut ModuleExtras::empty(),
            &packet,
            &addresses::RELAYER.signer()
        ),
        Err(crate::MiddlewareError::ForwardToNextMiddleware)
    ));

    assert!(orm.next.overflow_minted_coins.is_empty());
    assert!(orm.next.overflow_unescrowed_coins.is_empty());
    assert!(orm.next.overriden_packets_received.is_empty());
}

#[test]
fn error_on_underflow() {
    const TARGET: u64 = 150;
    const RECEIVED: u64 = 50;

    let packet = get_dummy_orm_packet(BASE_DENOM, TARGET, RECEIVED);

    let mut orm = get_dummy_orm();

    assert!(matches!(
        orm.on_recv_packet_execute_inner(
            &mut ModuleExtras::empty(),
            &packet,
            &addresses::RELAYER.signer()
        ),
        Err(crate::MiddlewareError::Message(err))
        if err == format!(
            "Target amount ({TARGET}) is greater than the \
             received amount ({RECEIVED})",
        )
    ));

    assert!(orm.next.overflow_minted_coins.is_empty());
    assert!(orm.next.overflow_unescrowed_coins.is_empty());
    assert!(orm.next.overriden_packets_received.is_empty());
}

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
    let packet = get_dummy_orm_packet(BASE_DENOM, 50, 100);
    _ = decode_ics20_msg(&packet).unwrap();
}

#[test]
fn decode_forward_msg_forwards_to_next_middleware_not_json() {
    let packet_data = PacketData {
        sender: addresses::BERTHA.signer(),
        receiver: addresses::CARLOS.signer(),
        token: Coin {
            amount: 100u64.into(),
            denom: BASE_DENOM.parse().unwrap(),
        },
        memo: String::new().into(),
    };
    let packet = Packet {
        data: serde_json::to_vec(&packet_data).unwrap(),
        ..get_dummy_orm_packet(BASE_DENOM, 50, 100)
    };

    assert!(matches!(
        decode_overflow_receive_msg::<OrmPacketMetadata>(&packet),
        Err(MiddlewareError::ForwardToNextMiddleware)
    ));
}

#[test]
fn decode_forward_msg_forwards_to_next_middleware_not_orm_msg() {
    let packet_data = PacketData {
        sender: addresses::BERTHA.signer(),
        receiver: addresses::CARLOS.signer(),
        token: Coin {
            amount: 100u64.into(),
            denom: BASE_DENOM.parse().unwrap(),
        },
        memo: r#"{"combo": "breaker"}"#.to_owned().into(),
    };
    let packet = Packet {
        data: serde_json::to_vec(&packet_data).unwrap(),
        ..get_dummy_orm_packet(BASE_DENOM, 50, 100)
    };

    assert!(matches!(
        decode_overflow_receive_msg::<OrmPacketMetadata>(&packet),
        Err(MiddlewareError::ForwardToNextMiddleware)
    ));
}

#[test]
fn decode_forward_msg_failure() {
    let packet_data = PacketData {
        sender: addresses::BERTHA.signer(),
        receiver: addresses::CARLOS.signer(),
        token: Coin {
            amount: 100u64.into(),
            denom: BASE_DENOM.parse().unwrap(),
        },
        memo: r#"{"overflow_receive": {"rip": ":("}}"#.to_owned().into(),
    };
    let packet = Packet {
        data: serde_json::to_vec(&packet_data).unwrap(),
        ..get_dummy_orm_packet(BASE_DENOM, 50, 100)
    };

    assert!(matches!(
        decode_overflow_receive_msg::<OrmPacketMetadata>(&packet),
        Err(MiddlewareError::Message(_))
    ));
}
