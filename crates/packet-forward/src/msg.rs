/*
type PacketMetadata struct {
    Forward *ForwardMetadata `json:"forward"`
}

type ForwardMetadata struct {
    Receiver string   `json:"receiver,omitempty"`
    Port     string   `json:"port,omitempty"`
    Channel  string   `json:"channel,omitempty"`
    Timeout  Duration `json:"timeout,omitempty"`
    Retries  *uint8   `json:"retries,omitempty"`

    // Using JSONObject so that objects for next property will not be mutated by golang's lexicographic key sort on map keys during Marshal.
    // Supports primitives for Unmarshal/Marshal so that an escaped JSON-marshaled string is also valid.
    Next *JSONObject `json:"next,omitempty"`
}
*/

pub struct PacketMetadata {
    forward: ForwardMetadata,
}

pub struct ForwardMetadata {
    // TODO
}
