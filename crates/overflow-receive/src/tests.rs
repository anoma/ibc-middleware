pub(crate) mod utils;

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
            orm.inject_failure(FailurePoint::MintCoinsValidate);

            assert_failure_injection(
                FailurePoint::MintCoinsValidate,
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
}
