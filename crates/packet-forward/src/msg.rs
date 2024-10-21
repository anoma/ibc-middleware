use alloc::string::{String, ToString};
use core::fmt;
use core::str::FromStr;

use ibc_core_host_types::identifiers::{ChannelId, PortId};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Hash, Clone)]
pub struct PacketMetadata {
    pub forward: ForwardMetadata,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Hash, Clone)]
pub struct ForwardMetadata {
    #[serde(deserialize_with = "deserialize_non_empty_str")]
    pub receiver: String,
    #[serde(deserialize_with = "deserialize_from_str")]
    pub port: PortId,
    #[serde(deserialize_with = "deserialize_from_str")]
    pub channel: ChannelId,
    pub timeout: Option<Duration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retries: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next: Option<serde_json::Map<String, serde_json::Value>>,
}

fn deserialize_non_empty_str<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    if !s.is_empty() {
        Ok(s)
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

    /// Duration type whose serialization routines are compatible with Strange Love's
    /// PFM JSON forward messages.
    #[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Serialize, Deserialize)]
    #[serde(from = "AllDuration")]
    #[repr(transparent)]
    pub struct Duration(#[serde(serialize_with = "serialize_to_str")] pub dur::Duration);

    #[cfg(test)]
    mod test_duration {
        use super::*;
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
                        receiver: "tnam1qrx3tphxjr9qaznadzykxzt4x76c0cm8ts3pwukt".to_owned(),
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
                        receiver: "tnam1qrx3tphxjr9qaznadzykxzt4x76c0cm8ts3pwukt".to_owned(),
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
                        receiver: "tnam1qrx3tphxjr9qaznadzykxzt4x76c0cm8ts3pwukt".to_owned(),
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
                        receiver: "tnam1qrx3tphxjr9qaznadzykxzt4x76c0cm8ts3pwukt".to_owned(),
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
