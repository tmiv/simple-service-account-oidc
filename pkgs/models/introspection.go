package models

type Introspection struct {
	Active    bool   `json:"active,omitempty"`
	Scope     string `json:"scope,omitempty"`
	ClientId  string `json:"client_id,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
}
