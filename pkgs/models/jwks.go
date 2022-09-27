package models

type JWK struct {
	Alg string   `json:"alg"`
	Kty string   `json:"kty"`
	Use string   `json:"use"`
	X5c []string `json:"x5c,omitempty"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5t string   `json:"x5t,omitempty"`
	KID string   `json:"kid,omitempty"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}
