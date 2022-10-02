package realmserver

import (
	"crypto/rsa"
	"fmt"
	"net/url"
	"regexp"
	"time"

	"github.com/golang-jwt/jwt"
)

type KeySourceType uint8

var (
	validServiceAccountName = regexp.MustCompile("^[a-z0-9A-Z\\._\\-]+$")
)

const (
	Undefined KeySourceType = iota
	JWKSFile
	JWKSUri
)

func (ks KeySourceType) String() string {
	switch ks {
	case JWKSFile:
		return "jwksFile"
	case JWKSUri:
		return "jwksUri"
	}
	return "unknown"
}

func (ks *KeySourceType) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var text string
	unmarshal(&text)
	if text == "jwksFile" {
		*ks = JWKSFile
		return nil
	}
	if text == "jwksUri" {
		*ks = JWKSUri
		return nil
	}
	return fmt.Errorf("Error unmarshalling KeySourceType value of \"%s\" must be jwksFile or jwksUri", text)
}

type ServiceAccountConfig struct {
	Name               string        `yaml:"name"`
	KeySource          KeySourceType `yaml:"keySource"`
	KeySourceCacheTime uint64        `yaml:"keySourceCacheTime"`
	KeySourceFilePath  string        `yaml:"keySourceFilePath"`
	KeySourceURI       string        `yaml:"keySourceURI"`
	Scopes             []string      `yaml:"scopes"`
	Roles              []string      `yaml:"roles"`
	TokenTTL           int           `yaml:"tokenTTL"`
}

type ServiceAccount struct {
	Config        *ServiceAccountConfig
	cachedJWKSUri *url.URL
	cachedKeys    map[string]*rsa.PublicKey
}

func CreateServiceAccount(config *ServiceAccountConfig) (*ServiceAccount, error) {
	sa := ServiceAccount{
		Config:     config,
		cachedKeys: make(map[string]*rsa.PublicKey, 0),
	}
	if !validServiceAccountName.Match([]byte(config.Name)) {
		return nil, fmt.Errorf("Must declare a valid name for service account")
	}
	if config.KeySource == Undefined {
		return nil, fmt.Errorf("Must declare a keysource for service account %s so it is not %s", config.Name, config.KeySource)
	}
	if config.KeySource == JWKSFile && len(config.KeySourceFilePath) == 0 {
		return nil, fmt.Errorf("Must declare a keysource file when keySource is %s", config.KeySource)
	}
	if config.KeySource == JWKSUri {
		url, err := url.ParseRequestURI(config.KeySourceURI)
		if err != nil {
			return nil, fmt.Errorf("Must declare a valid keysource uri when keySource is %s: %v", config.KeySource, err)
		}
		sa.cachedJWKSUri = url
	}
	return &sa, nil
}

func (sa *ServiceAccount) CheckJWT(tokenString string, expectedAud string) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		if key, ok := sa.cachedKeys[token.Header["kid"].(string)]; ok {
			return key, nil
		}
		return nil, fmt.Errorf("No associated key for id: %s", token.Header["kid"])
	})
	if err != nil {
		return nil, err
	}
	claims, _ := token.Claims.(*jwt.StandardClaims)
	exp := claims.ExpiresAt
	now := time.Now().UTC().Unix()
	if exp <= now {
		return nil, fmt.Errorf("Token Expired")
	}
	if sa.Config.Name != claims.Issuer {
		return nil, fmt.Errorf("Token has invalid issuer")
	}
	if sa.Config.Name != claims.Subject {
		return nil, fmt.Errorf("Token has invalid subject")
	}
	if expectedAud != claims.Audience {
		return nil, fmt.Errorf("Token has invalid audience")
	}
	return token, err
}
