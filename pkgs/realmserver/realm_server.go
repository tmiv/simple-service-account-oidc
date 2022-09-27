package realmserver

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"crypto/rand"
	"crypto/rsa"
	b64 "encoding/base64"
	"encoding/binary"
	"encoding/json"

	"pkgs/models"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

var (
	defaultClaims        []string = []string{"aud", "iss"}
	defaultGrantTypes    []string = []string{"client_credentials"}
	defaultSigningAlgs   []string = []string{"RS256", "RS512"}
	defaultResponseTypes []string = []string{"token"}
	defaultSubjectTypes  []string = []string{"public"}
)

type RealmConfig struct {
	Name            string                 `yaml:"name"`
	ClaimsSupported []string               `yaml:"claimsSupported"`
	ServiceAccounts []ServiceAccountConfig `yaml:"serviceAccounts"`
	KeyBits         int                    `yaml:"keyBits"`
	KeyRotationTime int                    `yaml:"keyRotationTime"`
}

type Key struct {
	KID        string
	PrivateKey *rsa.PrivateKey
}

type Realm struct {
	Config  *RealmConfig
	BaseURL url.URL
	KeySet  [2]Key

	accounts            []*ServiceAccount
	claimsMap           map[string]bool
	discoveryConfig     *models.DiscoveryConfig
	discoveryConfigJson []byte
	jwks                []byte
}

type RealmClaims struct {
	*jwt.StandardClaims
	Scope    string   `json:"scope"`
	ClientId string   `json:"clientId"`
	Role     []string `json:"role"`
}

func (realm *Realm) buildDiscoveryConfig() error {
	_, err := url.ParseRequestURI(realm.BaseURL.String())
	if len(realm.BaseURL.String()) == 0 || err != nil {
		return fmt.Errorf("Base URL is malformatted \"%s\" : %v", realm.BaseURL.String(), err)
	}
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
		SubjectTypesSupported:            defaultSubjectTypes,
	}
	realm.discoveryConfigJson, err = json.Marshal(realm.discoveryConfig)
	return err
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
		b := []byte{}
		b = trimLeftByte(binary.BigEndian.AppendUint64(b, uint64(pub.E)), 0)
		jwks.Keys[i] = models.JWK{
			Alg: "RS512",
			Kty: "RSA",
			Use: "sig",
			KID: pk.KID,
			N:   b64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E:   b64.RawURLEncoding.EncodeToString(b),
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
	if realm.discoveryConfig == nil || realm.discoveryConfigJson == nil {
		err := realm.buildDiscoveryConfig()
		if err != nil {
			log.Printf("Error building discovery confg %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(realm.discoveryConfigJson)
}

func (realm *Realm) serveAuth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
}

func (realm *Realm) serveRevocation(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
}

func (realm *Realm) serveJWKSUri(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(realm.jwks))
}

func (realm *Realm) serveIntrospection(w http.ResponseWriter, r *http.Request) {
	postType := r.Header["Content-Type"]
	if len(postType) != 1 || postType[0] != "application/x-www-form-urlencoded" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("{\"error\" : \"content type header must be application/x-www-form-urlencoded got %v\"}", postType)))
		return
	}
	tokenString := r.Form.Get("token")
	if len(tokenString) < 1 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("{\"error\" : \"no token\"}"))
		return
	}
	token, err := realm.CheckJWT(tokenString)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{\"active\" : false}"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	claims := token.Claims.(*RealmClaims)
	response, _ := json.Marshal(&models.Introspection{
		Active:    true,
		ClientId:  claims.ClientId,
		ExpiresAt: claims.ExpiresAt,
		Scope:     claims.Scope,
	})
	w.Write(response)
}

func (realm *Realm) serveToken(w http.ResponseWriter, r *http.Request) {
	postType := r.Header["Content-Type"]
	if len(postType) != 1 || postType[0] != "application/x-www-form-urlencoded" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("{\"error\" : \"content type header must be application/x-www-form-urlencoded got %v\"}", postType)))
		return
	}
	clientAssertionType := r.Form.Get("client_assertion_type")
	if clientAssertionType != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("{\"error\" : \"client_assertion_type must be urn:ietf:params:oauth:client-assertion-type:jwt-bearer got (%s)\"}", clientAssertionType)))
		return
	}
	grantType := r.Form.Get("grant_type")
	if grantType != "client_credentials" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("{\"error\" : \"grant_type must be client_credentials:jwt-bearer got (%s)\"}", grantType)))
		return
	}
	clientAssertion := r.Form.Get("client_assertion")
	if len(clientAssertion) <= 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("{\"error\" : \"a client_assertion is required got none\"}"))
		return
	}
	clientId := r.Form.Get("client_id")
	var account *ServiceAccount = nil
	for _, sa := range realm.accounts {
		if sa.Config.Name == clientId {
			account = sa
			break
		}
	}
	if account == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("{\"error\" : \"client_id (%s) could not be found\"}", clientId)))
		return
	}

	authorized, err := account.CheckJWT(clientAssertion, realm.discoveryConfig.Issuer)
	if authorized == nil || err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	claims, shouldReturn := realm.processClaims(r, w)
	if shouldReturn {
		return
	}
	claims["clientId"] = clientId
	if len(account.Config.Roles) > 0 {
		claims["role"] = account.Config.Roles
	}
	if len(account.Config.Scopes) > 0 {
		claims["scope"] = strings.Join(account.Config.Scopes, " ")
	}
	tokenString, err := buildJWTExpiresFromNow(realm.KeySet[1].PrivateKey, claims, clientId, realm.discoveryConfig.Issuer, uuid.NewString(), realm.KeySet[1].KID, int64(account.Config.TokenTTL))
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("{\"error\" : \"error (%v)\"}", err)))
		return
	}
	w.Header().Set("Content-Type", "application/jwt")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(tokenString))
}

func (realm *Realm) processClaims(r *http.Request, w http.ResponseWriter) (map[string]interface{}, bool) {
	claims := make(map[string]interface{}, 0)
	claimsString := r.Form.Get("claims")
	if len(claimsString) > 0 {
		err := json.Unmarshal([]byte(claimsString), &claims)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(fmt.Sprintf("{\"error\" : \"Could not parse claims %v\"}", err)))
			return nil, true
		}
		for c, _ := range claims {
			if _, ok := realm.claimsMap[c]; !ok {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(fmt.Sprintf("{\"error\" : \"claim %s is not supported\"}", c)))
				return nil, true
			}
		}
	}
	return claims, false
}

func buildJWT(key *rsa.PrivateKey, claims map[string]interface{}, audience string, issuer string, subject string, kid string, now time.Time, exp time.Time) (string, error) {
	allClaims := jwt.MapClaims{
		"iss": issuer,
		"sub": subject,
		"aud": audience,
		"exp": exp.Unix(),
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"jti": uuid.New().String(),
	}
	for cn, c := range claims {
		if _, ok := allClaims[cn]; !ok {
			allClaims[cn] = c
		} else {
			return "", fmt.Errorf("Double mapping of claim %s", cn)
		}
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS512, allClaims)
	token.Header["kid"] = kid
	keystring, _ := token.SignedString(key)
	return keystring, nil
}

func buildJWTExpiresFromNow(key *rsa.PrivateKey, claims map[string]interface{}, audience string, issuer string, subject string, kid string, timeToLive int64) (string, error) {
	now := time.Now().UTC()
	exp := time.Now().UTC().Add(time.Second * time.Duration(timeToLive))
	return buildJWT(key, claims, audience, issuer, subject, kid, now, exp)
}

func (realm *Realm) generateKey() error {
	realm.KeySet[0] = realm.KeySet[1]
	pk, err := rsa.GenerateKey(rand.Reader, realm.Config.KeyBits)
	if err != nil {
		return err
	}
	realm.KeySet[1] = Key{KID: uuid.New().String(), PrivateKey: pk}
	return nil
}

func (r *Realm) buildClaimMap() {
	r.claimsMap = make(map[string]bool, len(r.Config.ClaimsSupported))
	for _, c := range r.Config.ClaimsSupported {
		r.claimsMap[c] = true
	}
}

func (realm *Realm) CheckJWT(tokenString string) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(tokenString, &RealmClaims{}, func(token *jwt.Token) (interface{}, error) {
		for _, k := range realm.KeySet {
			if k.KID == token.Header["kid"].(string) {
				return &k.PrivateKey.PublicKey, nil
			}
		}
		return nil, fmt.Errorf("No associated key for id: %s", token.Header["kid"])
	})
	if err != nil {
		return nil, err
	}
	claims, _ := token.Claims.(*RealmClaims)
	if realm.discoveryConfig.Issuer != claims.Issuer {
		return nil, fmt.Errorf("Token has invalid issuer")
	}
	for _, sa := range realm.accounts {
		if sa.Config.Name == claims.Audience {
			return token, err
		}
	}
	return nil, fmt.Errorf("Token has invalid audience")
}

func CreateRealm(rc *RealmConfig, baseurl url.URL, router *mux.Router) (*Realm, error) {
	r := Realm{Config: rc, BaseURL: baseurl}
	for range []int{0, 1} {
		err := r.generateKey()
		if err != nil {
			return nil, err
		}
	}
	err := r.buildJWKS()
	if err != nil {
		return nil, err
	}
	r.buildClaimMap()
	r.accounts = make([]*ServiceAccount, len(rc.ServiceAccounts))
	for i, sac := range rc.ServiceAccounts {
		sa, err := CreateServiceAccount(&sac)
		if err != nil {
			return nil, err
		}
		r.accounts[i] = sa
	}
	err = r.buildDiscoveryConfig()
	if err != nil {
		return nil, err
	}
	configpath, err := url.JoinPath(r.BaseURL.Path, "realms", r.Config.Name, ".well-known/openid-configuration")
	if err != nil {
		return nil, err
	}
	configpath = "/" + configpath
	router.HandleFunc(configpath, r.serveDiscoveryConfig)
	u, err := url.ParseRequestURI(r.discoveryConfig.JWKSUri)
	if err != nil {
		return nil, err
	}
	router.HandleFunc(u.Path, r.serveJWKSUri)
	u, err = url.ParseRequestURI(r.discoveryConfig.AuthorizationEndpoint)
	if err != nil {
		return nil, err
	}
	router.HandleFunc(u.Path, r.serveAuth)
	u, err = url.ParseRequestURI(r.discoveryConfig.RevocationEndpoint)
	if err != nil {
		return nil, err
	}
	router.HandleFunc(u.Path, r.serveRevocation)
	u, err = url.ParseRequestURI(r.discoveryConfig.TokenEndpoint)
	if err != nil {
		return nil, err
	}
	router.HandleFunc(u.Path, r.serveToken).Methods("POST")
	u, err = url.ParseRequestURI(r.discoveryConfig.IntrospectionEndpoint)
	if err != nil {
		return nil, err
	}
	router.HandleFunc(u.Path, r.serveIntrospection).Methods("POST")
	return &r, nil
}
