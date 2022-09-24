package realmserver

import (
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"time"

	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	b64 "encoding/base64"
	"encoding/binary"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/tmiv/simple-service-account-oidc/pkgs/models"
)

var (
	defaultClaims        []string = []string{"aud", "iss"}
	defaultGrantTypes    []string = []string{"client_credentials"}
	defaultSigningAlgs   []string = []string{"RS256", "RS512"}
	defaultResponseTypes []string = []string{"token"}
)

type RealmConfig struct {
	Name            string           `yaml:"name"`
	ClaimsSupported []string         `yaml:"claimsSupported"`
	ServiceAccounts []ServiceAccount `yaml:"serviceAccounts"`
	KeyBits         int              `yaml:"keyBits"`
	KeyRotationTime int              `yaml:"keyRotationTime"`
}

type Key struct {
	KID        string
	CA         *x509.Certificate
	PrivateKey *rsa.PrivateKey
}

type Realm struct {
	Config  *RealmConfig
	BaseURL url.URL
	KeySet  [2]Key

	discoveryConfig *models.DiscoveryConfig
	jwks            []byte
}

func (realm *Realm) buildDiscoveryConfig() error {
	issuer_url := realm.BaseURL.JoinPath("realms", realm.Config.Name)
	realm.discoveryConfig = &models.DiscoveryConfig{
		Issuer:                           issuer_url.String(),
		AuthorizationEndpoint:            issuer_url.JoinPath("protocol/openid-connect/auth").String(),
		TokenEndpoint:                    issuer_url.JoinPath("protocol/openid-connect/token").String(),
		IntrospectionEndpoint:            issuer_url.JoinPath("protocol/openid-connect/token/introspect").String(),
		RevocationEndpoint:               issuer_url.JoinPath("protocol/openid-connect/token/revoke").String(),
		JWKSUri:                          issuer_url.JoinPath("protocol/openid-connect/certs").String(),
		IdTokenSigningAlgValuesSupported: defaultSigningAlgs,
		GrantTypesSupported:              defaultGrantTypes,
		ClaimsSupported:                  removeDuplicates(append(defaultClaims, realm.Config.ClaimsSupported...)),
		ScopesSupported:                  realm.collectScopes(),
		ReponseTypesSupported:            defaultResponseTypes,
	}
	return nil
}

func trimLeftByte(s []byte, c byte) []byte {
	for len(s) > 0 && s[0] == c {
		s = s[1:]
	}
	return s
}

func (realm *Realm) buildJWKS() error {
	jwks := models.JWKS{}
	jwks.Keys = make([]models.JWK, 2)
	for i, pk := range realm.KeySet {
		pub := pk.PrivateKey.PublicKey
		cert, err := x509.CreateCertificate(rand.Reader, pk.CA, pk.CA, &pub, pk.PrivateKey)
		if err != nil {
			return err
		}
		b := []byte{}
		b = trimLeftByte(binary.BigEndian.AppendUint64(b, uint64(pub.E)), 0)
		cert_finger := sha1.Sum(cert)
		jwks.Keys[i] = models.JWK{
			Alg: "RS512",
			Kty: "RSA",
			Use: "sig",
			X5c: []string{b64.URLEncoding.EncodeToString(cert)},
			N:   b64.URLEncoding.EncodeToString(pub.N.Bytes()),
			E:   b64.URLEncoding.EncodeToString(b),
			X5t: b64.URLEncoding.EncodeToString(cert_finger[:]),
		}
	}
	var err error
	realm.jwks, err = json.Marshal(jwks)
	return err
}

func (realm *Realm) collectScopes() []string {
	scopes := []string{}
	for _, sa := range realm.Config.ServiceAccounts {
		scopes = append(scopes, sa.Scopes...)
	}
	return removeDuplicates(scopes)
}

func removeDuplicates(strSlice []string) []string {
	allKeys := make(map[string]bool)
	list := []string{}
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}

func (realm *Realm) serveDiscoveryConfig(w http.ResponseWriter, r *http.Request) {
	if realm.discoveryConfig == nil {
		err := realm.buildDiscoveryConfig()
		if err != nil {
			log.Printf("Error building discovery confg %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
	bytes, err := json.Marshal(&realm.discoveryConfig)
	if err != nil {
		log.Printf("Error marshalling discovery %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(bytes)
}

func (realm *Realm) serveRevocation(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
}

func (realm *Realm) serveJWKSUri(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(realm.jwks))
}
func (realm *Realm) serveToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

}

func (realm *Realm) generateKey() error {
	realm.KeySet[0] = realm.KeySet[1]
	pk, err := rsa.GenerateKey(rand.Reader, realm.Config.KeyBits)
	if err != nil {
		return err
	}
	realm.KeySet[1] = Key{KID: uuid.New().String(), PrivateKey: pk, CA: &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Second * time.Duration(realm.Config.KeyRotationTime*2)),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	},
	}
	return nil
}

func Create(rc *RealmConfig, baseurl url.URL, router *mux.Router) error {
	r := Realm{Config: rc, BaseURL: baseurl}
	for _, _ = range []int{0, 1} {
		err := r.generateKey()
		if err != nil {
			return err
		}
	}
	err := r.buildJWKS()
	if err != nil {
		return err
	}
	fmt.Println(string(r.jwks))
	r.buildDiscoveryConfig()
	configpath, err := url.JoinPath(r.BaseURL.Path, "realms", r.Config.Name, ".well-known/openid-configuration")
	if err != nil {
		return err
	}
	router.HandleFunc(configpath, r.serveDiscoveryConfig)
	u, err := url.Parse(r.discoveryConfig.JWKSUri)
	if err != nil {
		return err
	}
	router.HandleFunc(u.Path, r.serveJWKSUri)
	u, err = url.Parse(r.discoveryConfig.RevocationEndpoint)
	if err != nil {
		return err
	}
	router.HandleFunc(u.Path, r.serveRevocation)
	u, err = url.Parse(r.discoveryConfig.TokenEndpoint)
	if err != nil {
		return err
	}
	router.HandleFunc(u.Path, r.serveToken)
	return nil
}
