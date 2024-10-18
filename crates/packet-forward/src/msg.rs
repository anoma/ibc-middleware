use core::fmt;
use core::str::FromStr;
use alloc::string::{String, ToString};

use ibc_core_host_types::identifiers::{ChannelId, PortId};
use serde::{Deserializer, Deserialize, Serializer, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct PacketMetadata {
    pub forward: ForwardMetadata,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ForwardMetadata {
    #[serde(deserialize_with = "deserialize_from_str")]
    pub port: PortId,
    #[serde(deserialize_with = "deserialize_from_str")]
    pub channel: ChannelId,
    pub timeout: Duration,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retries: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next: Option<serde_json::Map<String, serde_json::Value>>,
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

    #[derive(Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Serialize, Deserialize)]
    #[serde(from = "AllDuration")]
    #[repr(transparent)]
    pub struct Duration(
        #[serde(serialize_with = "serialize_to_str")]
        pub dur::Duration,
    );

    #[cfg(test)]
    mod test_duration {
        use super::*;

        #[test]
        fn serde_roundtrip_parsing() {
            const DUR_STR: &str = "\"1m5s\"";
            const DUR_F64: &str = "1.2345";

            let expected_from_str = Duration(dur::Duration::from_secs(65));
            let expected_from_f64 = Duration(dur::Duration::from_nanos(1));

            let parsed: Duration = serde_json::from_str(DUR_STR).unwrap();
            assert_eq!(parsed, expected_from_str);

            let parsed: Duration = serde_json::from_str(DUR_F64).unwrap();
            assert_eq!(parsed, expected_from_f64);
        }
    }
}
