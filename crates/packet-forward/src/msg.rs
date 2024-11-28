use alloc::string::{String, ToString};
use core::fmt;
use core::str::FromStr;

use ibc_core_host_types::identifiers::{ChannelId, PortId};
use ibc_primitives::Signer;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Metadata included in ICS-20 packet memos.
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Hash, Clone)]
pub struct PacketMetadata {
    /// Packet forward middleware metadata.
    pub forward: ForwardMetadata,
}

/// Metadata included in ICS-20 packet memos,
/// related with the packet forwarding middleware.
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Hash, Clone)]
pub struct ForwardMetadata {
    /// Receiver account on the destination chain.
    #[serde(deserialize_with = "deserialize_non_empty_signer")]
    pub receiver: Signer,
    /// Destination port (usually the `transfer` port).
    #[serde(deserialize_with = "deserialize_from_str")]
    pub port: PortId,
    /// Destination channel.
    #[serde(deserialize_with = "deserialize_from_str")]
    pub channel: ChannelId,
    /// Packet timeout duration.
    ///
    /// Formatted as regular time strings (e.g. `"1m20s"`),
    /// or nanoseconds (e.g. `12345`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<Duration>,
    /// The number of retries before a packet is invalidated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retries: Option<u8>,
    /// The memo of the next forward transfer. This might be
    /// another [`ForwardMetadata`] structure, along with
    /// any additional middleware callbacks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next: Option<serde_json::Map<String, serde_json::Value>>,
}

fn deserialize_non_empty_signer<'de, D>(deserializer: D) -> Result<Signer, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    if !s.is_empty() {
        Ok(s.into())
    } else {
        Err(serde::de::Error::custom(
            "IBC forward receiver cannot be empty",
        ))
    }
}

fn deserialize_from_str<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr,
    T::Err: fmt::Display,
{
    let s = String::deserialize(deserializer)?;
    T::from_str(&s).map_err(serde::de::Error::custom)
}

fn serialize_to_str<S, T>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: fmt::Display,
{
    serializer.serialize_str(&value.to_string())
}

#[doc(inline)]
pub use duration::Duration;

mod duration {
    #[cfg(feature = "borsh")]
    use borsh::{BorshDeserialize, BorshSerialize};

    use super::*;

    #[derive(Debug, Serialize, Deserialize)]
    struct DurrDerp(
        #[serde(deserialize_with = "deserialize_from_str")]
        #[serde(serialize_with = "serialize_to_str")]
        dur::Duration,
    );

    impl From<f64> for F64Dur {
        fn from(dur: f64) -> Self {
            Self(DurrDerp(dur::Duration::from_nanos(dur as u128)))
        }
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(from = "f64")]
    struct F64Dur(DurrDerp);

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(untagged)]
    enum AllDuration {
        Dur(DurrDerp),
        F64(F64Dur),
    }

    impl From<AllDuration> for Duration {
        fn from(dur: AllDuration) -> Self {
            match dur {
                AllDuration::Dur(DurrDerp(dur)) => Self(dur),
                AllDuration::F64(F64Dur(DurrDerp(dur))) => Self(dur),
            }
        }
    }

    impl Duration {
        /// Initialize a new [`Duration`].
        pub const fn from_dur(dur: dur::Duration) -> Self {
            Self(dur)
        }
    }

    /// Duration type whose serialization routines are compatible with Strange Love's
    /// PFM JSON forward messages.
    #[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Serialize, Deserialize)]
    #[serde(from = "AllDuration")]
    #[repr(transparent)]
    pub struct Duration(#[serde(serialize_with = "serialize_to_str")] pub dur::Duration);

    #[cfg(feature = "borsh")]
    impl BorshSerialize for Duration {
        fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
            let nanos = self.0.as_nanos().to_le_bytes();
            writer.write_all(&nanos)
        }
    }

    #[cfg(feature = "borsh")]
    impl BorshDeserialize for Duration {
        fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Duration> {
            let mut buf = [0u8; 16];
            reader.read_exact(&mut buf)?;

            let nanos = u128::from_le_bytes(buf);
            Ok(Duration(dur::Duration::from_nanos(nanos)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_serde_roundtrip_parsing() {
        const DUR_STR: &str = "\"1m5s\"";
        const DUR_F64: &str = "1.2345";

        let expected_from_str = Duration(dur::Duration::from_secs(65));
        let expected_from_f64 = Duration(dur::Duration::from_nanos(1));

        let parsed: Duration = serde_json::from_str(DUR_STR).unwrap();
        assert_eq!(parsed, expected_from_str);

        let parsed: Duration = serde_json::from_str(DUR_F64).unwrap();
        assert_eq!(parsed, expected_from_f64);
    }

    #[test]
    fn forward_msg_parsing() {
        struct TestCase {
            raw_json: &'static str,
            expected: Result<PacketMetadata, ()>,
        }

        impl TestCase {
            fn assert(self) {
                let parsed = serde_json::from_str::<PacketMetadata>(self.raw_json).map_err(|_| ());
                assert_eq!(parsed, self.expected);
            }
        }

        let cases = [
            TestCase {
                raw_json: r#"
                    {
                      "forward": {
                        "channel": "channel-1180",
                        "port": "transfer",
                        "receiver": "tnam1qrx3tphxjr9qaznadzykxzt4x76c0cm8ts3pwukt"
                      },
                      "ibc_callback": "osmo1ewll8h7up3g0ca2z9ur9e6dv6an64snxg5k8tmzylg6uprkyhgzszjgdzr"
                    }
                "#,
                expected: Ok(PacketMetadata {
                    forward: ForwardMetadata {
                        receiver: "tnam1qrx3tphxjr9qaznadzykxzt4x76c0cm8ts3pwukt"
                            .to_owned()
                            .into(),
                        port: PortId::transfer(),
                        channel: ChannelId::new(1180),
                        timeout: None,
                        retries: None,
                        next: None,
                    },
                }),
            },
            TestCase {
                raw_json: r#"
                    {
                      "forward": {
                        "channel": "channel-1180",
                        "port": "transfer",
                        "receiver": "tnam1qrx3tphxjr9qaznadzykxzt4x76c0cm8ts3pwukt"
                      }
                    }
                "#,
                expected: Ok(PacketMetadata {
                    forward: ForwardMetadata {
                        receiver: "tnam1qrx3tphxjr9qaznadzykxzt4x76c0cm8ts3pwukt"
                            .to_owned()
                            .into(),
                        port: PortId::transfer(),
                        channel: ChannelId::new(1180),
                        timeout: None,
                        retries: None,
                        next: None,
                    },
                }),
            },
            TestCase {
                raw_json: r#"
                    {
                      "forward": {
                        "channel": "channel-1180",
                        "port": "transfer",
                        "receiver": "tnam1qrx3tphxjr9qaznadzykxzt4x76c0cm8ts3pwukt",
                        "next": {
                            "forward": {
                                "receiver": "noble18st0wqx84av8y6xdlss9d6m2nepyqwj6nfxxuv",
                                "channel": "channel-1181",
                                "port": "transfer"
                            }
                        }
                      }
                    }
                "#,
                expected: Ok(PacketMetadata {
                    forward: ForwardMetadata {
                        receiver: "tnam1qrx3tphxjr9qaznadzykxzt4x76c0cm8ts3pwukt"
                            .to_owned()
                            .into(),
                        port: PortId::transfer(),
                        channel: ChannelId::new(1180),
                        timeout: None,
                        retries: None,
                        next: Some(serde_json::Map::from_iter([(
                            "forward".to_owned(),
                            serde_json::Value::Object(serde_json::Map::from_iter([
                                (
                                    "receiver".to_owned(),
                                    serde_json::Value::String(
                                        "noble18st0wqx84av8y6xdlss9d6m2nepyqwj6nfxxuv".to_owned(),
                                    ),
                                ),
                                (
                                    "channel".to_owned(),
                                    serde_json::Value::String("channel-1181".to_owned()),
                                ),
                                (
                                    "port".to_owned(),
                                    serde_json::Value::String("transfer".to_owned()),
                                ),
                            ])),
                        )])),
                    },
                }),
            },
            TestCase {
                raw_json: r#"
                    {
                      "forwar": {
                        "channel": "channel-1180",
                        "port": "transfer",
                        "receiver": "tnam1qrx3tphxjr9qaznadzykxzt4x76c0cm8ts3pwukt"
                      }
                    }
                "#,
                expected: Err(()),
            },
            TestCase {
                raw_json: r#"
                    {
                      "forward": {
                        "channel": "channel-",
                        "port": "transfer",
                        "receiver": "tnam1qrx3tphxjr9qaznadzykxzt4x76c0cm8ts3pwukt"
                      }
                    }
                "#,
                expected: Err(()),
            },
            TestCase {
                raw_json: r#"
                    {
                      "forward": {
                        "channel": "channel-1234",
                        "port": "transfer",
                        "receiver": ""
                      }
                    }
                "#,
                expected: Err(()),
            },
            TestCase {
                raw_json: r#"
                    {
                      "forward": {
                        "channel": "channel-1180",
                        "port": "transfer",
                        "timeout": "1m20s",
                        "receiver": "tnam1qrx3tphxjr9qaznadzykxzt4x76c0cm8ts3pwukt"
                      }
                    }
                "#,
                expected: Ok(PacketMetadata {
                    forward: ForwardMetadata {
                        receiver: "tnam1qrx3tphxjr9qaznadzykxzt4x76c0cm8ts3pwukt"
                            .to_owned()
                            .into(),
                        port: PortId::transfer(),
                        channel: ChannelId::new(1180),
                        timeout: Some(Duration(dur::Duration::from_secs(80))),
                        retries: None,
                        next: None,
                    },
                }),
            },
        ];

        for case in cases {
            case.assert();
        }
    }
}
