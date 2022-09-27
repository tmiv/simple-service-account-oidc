package models

type DiscoveryConfig struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	JWKSUri                          string   `json:"jwks_uri"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	IntrospectionEndpoint            string   `json:"introspection_endpoint"`
	RevocationEndpoint               string   `json:"revocation_endpoint"`
	ReponseTypesSupported            []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IdTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	GrantTypesSupported              []string `json:"grant_types_supported"`
	ClaimsSupported                  []string `json:"claims_supported"`
	ScopesSupported                  []string `json:"scopes_supported"`
}
