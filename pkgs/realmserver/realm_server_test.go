package realmserver

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"pkgs/models"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
)

func TestRealmDiscovery(t *testing.T) {
	realm := Realm{
		Config: &RealmConfig{
			Name: "realm-a",
			ServiceAccounts: []ServiceAccountConfig{
				{Scopes: []string{"a.b.c", "a.b.d"}},
				{Scopes: []string{"a.b.e", "a.b.d"}},
			},
		},
		BaseURL: url.URL{
			Host:   "example.com",
			Path:   "base/path",
			Scheme: "https",
		},
	}

	request := &http.Request{}
	response := httptest.NewRecorder()

	realm.serveDiscoveryConfig(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("Bad Response")
	}

	dc := models.DiscoveryConfig{}
	err := json.Unmarshal(response.Body.Bytes(), &dc)
	if err != nil {
		t.Fatalf("Unmarshal Failed")
	}

	if dc.Issuer != "https://example.com/base/path/realms/realm-a" {
		t.Fatalf("Issuer Address Incorrect \"%s\"", dc.Issuer)
	}

	hasRS256 := false
	for _, a := range dc.IdTokenSigningAlgValuesSupported {
		if a == "RS256" {
			hasRS256 = true
		}
	}
	if !hasRS256 {
		t.Fatalf("id_token_signing_alg_values supported must contain RS256")
	}

	if len(dc.ScopesSupported) != 3 {
		t.Fatalf("Incorrect number of scopes")
	}
}

func TestRealm_serveAuth(t *testing.T) {
	realm := Realm{}
	request := &http.Request{}
	response := httptest.NewRecorder()

	realm.serveAuth(response, request)
	if response.Result().StatusCode != http.StatusNotImplemented {
		t.Fatalf("bad return value")
	}
}

func TestRealm_serveRevocation(t *testing.T) {
	realm := Realm{}
	request := &http.Request{}
	response := httptest.NewRecorder()

	realm.serveRevocation(response, request)
	if response.Result().StatusCode != http.StatusNotImplemented {
		t.Fatalf("bad return value")
	}
}

func TestRealm_serveJWKSUri(t *testing.T) {
	realm := Realm{
		jwks: []byte("testing_value"),
	}
	request := &http.Request{}
	response := httptest.NewRecorder()

	realm.serveJWKSUri(response, request)
	if response.Result().StatusCode != http.StatusOK {
		t.Fatalf("bad return value")
	}
	result := make([]byte, 100)
	read, err := response.Result().Body.Read(result)
	if err != nil {
		t.Fatalf("error reading result %v", err)
	}
	if string(result[:read]) != "testing_value" {
		t.Fatalf("bad return value %s", string(result))
	}
}

func TestRealm_generateKey(t *testing.T) {
	type fields struct {
		Config          *RealmConfig
		BaseURL         url.URL
		KeySet          [2]Key
		discoveryConfig *models.DiscoveryConfig
		jwks            []byte
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Bad Key Size",
			fields: fields{
				Config: &RealmConfig{
					KeyBits: 0,
				},
			},
			wantErr: true,
		},
		{
			name: "Good Build",
			fields: fields{
				Config: &RealmConfig{
					KeyBits: 512,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			realm := &Realm{
				Config:          tt.fields.Config,
				BaseURL:         tt.fields.BaseURL,
				KeySet:          tt.fields.KeySet,
				discoveryConfig: tt.fields.discoveryConfig,
				jwks:            tt.fields.jwks,
			}
			if err := realm.generateKey(); (err != nil) != tt.wantErr {
				t.Errorf("Realm.generateKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRealm_serveDiscoveryConfig(t *testing.T) {
	type fields struct {
		Config          *RealmConfig
		BaseURL         url.URL
		KeySet          [2]Key
		discoveryConfig *models.DiscoveryConfig
		jwks            []byte
	}
	type args struct {
		w http.ResponseWriter
		r *http.Request
	}
	tests := []struct {
		name               string
		fields             fields
		expectedReturnCode int
	}{
		{
			name:               "Bad discovery config",
			expectedReturnCode: http.StatusInternalServerError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			realm := &Realm{
				Config:          tt.fields.Config,
				BaseURL:         tt.fields.BaseURL,
				KeySet:          tt.fields.KeySet,
				discoveryConfig: tt.fields.discoveryConfig,
				jwks:            tt.fields.jwks,
			}
			request := &http.Request{}
			response := httptest.NewRecorder()

			realm.serveDiscoveryConfig(response, request)
			if response.Result().StatusCode != tt.expectedReturnCode {
				t.Fatalf("bad return value")
			}
		})
	}
}

func TestCreateRealm(t *testing.T) {
	type args struct {
		rc      *RealmConfig
		baseurl *url.URL
		router  *mux.Router
	}
	goodURL, _ := url.Parse("http://test.com/")
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Bad Service Account",
			args: args{
				rc: &RealmConfig{
					KeyBits:         512,
					ServiceAccounts: []ServiceAccountConfig{{Name: "account-a"}},
				},
				baseurl: goodURL,
				router:  mux.NewRouter(),
			},
			wantErr: true,
		},
		{
			name: "Good Run",
			args: args{
				rc: &RealmConfig{
					KeyBits: 512,
					ServiceAccounts: []ServiceAccountConfig{
						{Name: "account-a", KeySource: JWKSFile, KeySourceFilePath: "test.json"},
						{Name: "account-b", KeySource: JWKSFile, KeySourceFilePath: "test.json"},
					},
				},
				baseurl: goodURL,
				router:  mux.NewRouter(),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CreateRealm(tt.args.rc, *tt.args.baseurl, tt.args.router)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateRealm() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func ignoreError(val string, err error) string {
	return val
}

func TestRealm_serveToken(t *testing.T) {
	type fields struct {
		Config              *RealmConfig
		BaseURL             url.URL
		KeySet              [2]Key
		serviceAccounts     []*ServiceAccount
		discoveryConfig     *models.DiscoveryConfig
		discoveryConfigJson []byte
		jwks                []byte
	}
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	tests := []struct {
		name               string
		fields             fields
		header             map[string][]string
		form               url.Values
		expectedReturnCode int
	}{
		{
			name: "Incorrect Content Type",
			fields: fields{
				Config: &RealmConfig{
					ClaimsSupported: []string{"claim01"},
				},
			},
			expectedReturnCode: http.StatusBadRequest,
		},
		{
			name: "Incorrect Client Assertion Type",
			fields: fields{
				Config: &RealmConfig{
					ClaimsSupported: []string{"claim01"},
				},
			},
			header:             map[string][]string{"Content-Type": {"application/x-www-form-urlencoded"}},
			form:               url.Values{},
			expectedReturnCode: http.StatusBadRequest,
		},
		{
			name: "Incorrect Grant Type",
			fields: fields{
				Config: &RealmConfig{
					ClaimsSupported: []string{"claim01"},
				},
			},
			header:             map[string][]string{"Content-Type": {"application/x-www-form-urlencoded"}},
			form:               map[string][]string{"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}},
			expectedReturnCode: http.StatusBadRequest,
		},
		{
			name: "Incorrect Client ID",
			fields: fields{
				Config: &RealmConfig{
					ClaimsSupported: []string{"claim01"},
				},
				serviceAccounts: []*ServiceAccount{{Config: &ServiceAccountConfig{Name: "account-a"},
					cachedKeys: map[string]*rsa.PublicKey{"key1": &privateKey.PublicKey}}},
				discoveryConfig: &models.DiscoveryConfig{Issuer: "http://test.com/realms/account-a"},
			},
			header: map[string][]string{"Content-Type": {"application/x-www-form-urlencoded"}},
			form: map[string][]string{
				"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
				"grant_type":            {"client_credentials"},
				"client_id":             {"account-b"},
				"client_assertion":      {ignoreError(buildJWTExpiresFromNow(privateKey, make(map[string]interface{}, 0), "http://test.com/realms/account-a", "account-a", "account-a", "key1", 30))},
			},
			expectedReturnCode: http.StatusBadRequest,
		},
		{
			name: "No Client Assertion",
			fields: fields{
				Config: &RealmConfig{
					ClaimsSupported: []string{"claim01"},
				},
			},
			header: map[string][]string{"Content-Type": {"application/x-www-form-urlencoded"}},
			form: map[string][]string{
				"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
				"grant_type":            {"client_credentials"},
				"client_id":             {"account-a"},
			},
			expectedReturnCode: http.StatusBadRequest,
		},
		{
			name: "Invalid Key",
			fields: fields{
				Config: &RealmConfig{
					ClaimsSupported: []string{"claim01"},
				},
				serviceAccounts: []*ServiceAccount{{Config: &ServiceAccountConfig{Name: "account-a"},
					cachedKeys: map[string]*rsa.PublicKey{"key1": &privateKey.PublicKey}}},
				discoveryConfig: &models.DiscoveryConfig{Issuer: "http://test.com/realms/account-a"},
			},
			header: map[string][]string{"Content-Type": {"application/x-www-form-urlencoded"}},
			form: map[string][]string{
				"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
				"grant_type":            {"client_credentials"},
				"client_id":             {"account-a"},
				"client_assertion":      {"pk"},
			},
			expectedReturnCode: http.StatusUnauthorized,
		},
		{
			name: "Bad Claim",
			fields: fields{
				Config: &RealmConfig{
					ClaimsSupported: []string{},
				},
				serviceAccounts: []*ServiceAccount{{Config: &ServiceAccountConfig{Name: "account-a"},
					cachedKeys: map[string]*rsa.PublicKey{"key1": &privateKey.PublicKey}}},
				discoveryConfig: &models.DiscoveryConfig{Issuer: "http://test.com/realms/account-a"},
				KeySet:          [2]Key{{}, {PrivateKey: privateKey, KID: "key1"}},
			},
			header: map[string][]string{"Content-Type": {"application/x-www-form-urlencoded"}},
			form: map[string][]string{
				"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
				"grant_type":            {"client_credentials"},
				"client_id":             {"account-a"},
				"claims":                {"{\"claim01\" : \"value 01\"}"},
				"client_assertion":      {ignoreError(buildJWTExpiresFromNow(privateKey, make(map[string]interface{}, 0), "http://test.com/realms/account-a", "account-a", "account-a", "key1", 30))},
			},
			expectedReturnCode: http.StatusBadRequest,
		},
		{
			name: "Bad Claim List",
			fields: fields{
				Config: &RealmConfig{
					ClaimsSupported: []string{"exp"},
				},
				serviceAccounts: []*ServiceAccount{{Config: &ServiceAccountConfig{Name: "account-a"},
					cachedKeys: map[string]*rsa.PublicKey{"key1": &privateKey.PublicKey}}},
				discoveryConfig: &models.DiscoveryConfig{Issuer: "http://test.com/realms/account-a"},
				KeySet:          [2]Key{{}, {PrivateKey: privateKey, KID: "key1"}},
			},
			header: map[string][]string{"Content-Type": {"application/x-www-form-urlencoded"}},
			form: map[string][]string{
				"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
				"grant_type":            {"client_credentials"},
				"client_id":             {"account-a"},
				"claims":                {"--"},
				"client_assertion":      {ignoreError(buildJWTExpiresFromNow(privateKey, make(map[string]interface{}, 0), "http://test.com/realms/account-a", "account-a", "account-a", "key1", 30))},
			},
			expectedReturnCode: http.StatusBadRequest,
		},
		{
			name: "Double Claim",
			fields: fields{
				Config: &RealmConfig{
					ClaimsSupported: []string{"exp"},
				},
				serviceAccounts: []*ServiceAccount{{Config: &ServiceAccountConfig{Name: "account-a"},
					cachedKeys: map[string]*rsa.PublicKey{"key1": &privateKey.PublicKey}}},
				discoveryConfig: &models.DiscoveryConfig{Issuer: "http://test.com/realms/account-a"},
				KeySet:          [2]Key{{}, {PrivateKey: privateKey, KID: "key1"}},
			},
			header: map[string][]string{"Content-Type": {"application/x-www-form-urlencoded"}},
			form: map[string][]string{
				"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
				"grant_type":            {"client_credentials"},
				"client_id":             {"account-a"},
				"claims":                {"{\"exp\" : 1}"},
				"client_assertion":      {ignoreError(buildJWTExpiresFromNow(privateKey, make(map[string]interface{}, 0), "http://test.com/realms/account-a", "account-a", "account-a", "key1", 30))},
			},
			expectedReturnCode: http.StatusBadRequest,
		},
		{
			name: "Success",
			fields: fields{
				Config: &RealmConfig{
					ClaimsSupported: []string{"claim01"},
				},
				serviceAccounts: []*ServiceAccount{{
					Config: &ServiceAccountConfig{
						Name:   "account-a",
						Roles:  []string{"main-role"},
						Scopes: []string{"a.b.c", "d.e.f"},
					},
					cachedKeys: map[string]*rsa.PublicKey{"key1": &privateKey.PublicKey},
				}},
				discoveryConfig: &models.DiscoveryConfig{Issuer: "http://test.com/realms/account-a"},
				KeySet:          [2]Key{{}, {PrivateKey: privateKey, KID: "key1"}},
			},
			header: map[string][]string{"Content-Type": {"application/x-www-form-urlencoded"}},
			form: map[string][]string{
				"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
				"grant_type":            {"client_credentials"},
				"client_id":             {"account-a"},
				"claims":                {"{\"claim01\" : \"value 01\"}"},
				"client_assertion":      {ignoreError(buildJWTExpiresFromNow(privateKey, make(map[string]interface{}, 0), "http://test.com/realms/account-a", "account-a", "account-a", "key1", 30))},
			},
			expectedReturnCode: http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			realm := &Realm{
				Config:              tt.fields.Config,
				BaseURL:             tt.fields.BaseURL,
				KeySet:              tt.fields.KeySet,
				discoveryConfig:     tt.fields.discoveryConfig,
				discoveryConfigJson: tt.fields.discoveryConfigJson,
				accounts:            tt.fields.serviceAccounts,
				jwks:                tt.fields.jwks,
			}
			request := &http.Request{
				Header: tt.header,
				Form:   tt.form,
			}
			response := httptest.NewRecorder()

			realm.buildClaimMap()
			realm.serveToken(response, request)
			if response.Result().StatusCode != tt.expectedReturnCode {
				t.Fatalf("Return code %d did not match expected %d with result %s", response.Result().StatusCode, tt.expectedReturnCode, string(response.Body.Bytes()))
			}
		})
	}
}

func Test_buildJWT(t *testing.T) {
	type args struct {
		key      *rsa.PrivateKey
		claims   map[string]interface{}
		audience string
		issuer   string
		subject  string
		kid      string
		now      time.Time
		exp      time.Time
	}
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Double Claim",
			args: args{
				key:    privateKey,
				claims: map[string]interface{}{"aud": "hello"},
				now:    time.Now().UTC(),
			},
			wantErr: true,
		},
		{
			name: "Good",
			args: args{
				key:    privateKey,
				claims: map[string]interface{}{"good_name": "hello"},
				now:    time.Now().UTC(),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := buildJWT(tt.args.key, tt.args.claims, tt.args.audience, tt.args.issuer, tt.args.subject, tt.args.kid, tt.args.now, tt.args.exp)
			if (err != nil) != tt.wantErr {
				t.Errorf("buildJWT() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestRealm_CheckJWT(t *testing.T) {
	type fields struct {
		Config          *RealmConfig
		BaseURL         url.URL
		KeySet          [2]Key
		accounts        []*ServiceAccount
		discoveryConfig *models.DiscoveryConfig
		exp             time.Time
		now             time.Time
		aud             string
		keyName         string
		issuer          string
		subject         string
		claims          map[string]interface{}
	}
	type args struct {
		tokenString string
	}
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *jwt.Token
		wantErr bool
	}{
		{
			name: "Success",
			fields: fields{
				KeySet:  [2]Key{{KID: "k1", PrivateKey: privKey}, {KID: "k2", PrivateKey: nil}},
				keyName: "k1",
				exp:     time.Now().UTC().Add(time.Second * time.Duration(30)),
				issuer:  "issuer-string",
				aud:     "sa1",
				accounts: []*ServiceAccount{
					{Config: &ServiceAccountConfig{Name: "sa1"}},
				},
				discoveryConfig: &models.DiscoveryConfig{
					Issuer: "issuer-string",
				},
			},
		},
		{
			name: "No Key",
			fields: fields{
				KeySet:  [2]Key{{KID: "k6", PrivateKey: privKey}, {KID: "k2", PrivateKey: nil}},
				keyName: "k1",
				exp:     time.Now().UTC().Add(time.Second * time.Duration(30)),
				issuer:  "issuer-string",
				aud:     "sa1",
				accounts: []*ServiceAccount{
					{Config: &ServiceAccountConfig{Name: "sa1"}},
				},
				discoveryConfig: &models.DiscoveryConfig{
					Issuer: "issuer-string",
				},
			},
			wantErr: true,
		},
		{
			name: "Expired",
			fields: fields{
				KeySet:  [2]Key{{KID: "k1", PrivateKey: privKey}, {KID: "k2", PrivateKey: nil}},
				keyName: "k1",
				exp:     time.Now().UTC().Add(time.Second * time.Duration(-30)),
				issuer:  "issuer-string",
				aud:     "sa1",
				accounts: []*ServiceAccount{
					{Config: &ServiceAccountConfig{Name: "sa1"}},
				},
				discoveryConfig: &models.DiscoveryConfig{
					Issuer: "issuer-string",
				},
			},
			wantErr: true,
		},
		{
			name: "Bad Audience",
			fields: fields{
				KeySet:  [2]Key{{KID: "k1", PrivateKey: privKey}, {KID: "k2", PrivateKey: nil}},
				keyName: "k1",
				exp:     time.Now().UTC().Add(time.Second * time.Duration(30)),
				issuer:  "issuer-string",
				aud:     "sa2",
				accounts: []*ServiceAccount{
					{Config: &ServiceAccountConfig{Name: "sa1"}},
				},
				discoveryConfig: &models.DiscoveryConfig{
					Issuer: "issuer-string",
				},
			},
			wantErr: true,
		},
		{
			name: "Bad Issuer",
			fields: fields{
				KeySet:  [2]Key{{KID: "k1", PrivateKey: privKey}, {KID: "k2", PrivateKey: nil}},
				keyName: "k1",
				exp:     time.Now().UTC().Add(time.Second * time.Duration(30)),
				issuer:  "bad-issuer-string",
				aud:     "sa1",
				accounts: []*ServiceAccount{
					{Config: &ServiceAccountConfig{Name: "sa1"}},
				},
				discoveryConfig: &models.DiscoveryConfig{
					Issuer: "issuer-string",
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			realm := &Realm{
				Config:          tt.fields.Config,
				BaseURL:         tt.fields.BaseURL,
				KeySet:          tt.fields.KeySet,
				accounts:        tt.fields.accounts,
				discoveryConfig: tt.fields.discoveryConfig,
			}

			tokenString, err := buildJWT(privKey, tt.fields.claims, tt.fields.aud, tt.fields.issuer, tt.fields.subject, tt.fields.keyName, tt.fields.now, tt.fields.exp)
			_, err = realm.CheckJWT(tokenString)
			if (err != nil) != tt.wantErr {
				t.Errorf("Realm.CheckJWT() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestRealm_serveIntrospection(t *testing.T) {
	type fields struct {
		Config              *RealmConfig
		BaseURL             url.URL
		KeySet              [2]Key
		accounts            []*ServiceAccount
		claimsMap           map[string]bool
		discoveryConfig     *models.DiscoveryConfig
		discoveryConfigJson []byte
		jwks                []byte
	}
	type args struct {
		w http.ResponseWriter
		r *http.Request
	}
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	claims := map[string]interface{}{
		"clientId": "sa1",
		"scope":    "a.b.c c.d.e",
	}
	expire := time.Now().Add(time.Second * time.Duration(30))
	tokenString, _ := buildJWT(privKey, claims,
		"sa1", "issuer-string", "rand", "k1", time.Now().UTC(), expire)
	tests := []struct {
		name               string
		fields             fields
		args               args
		header             map[string][]string
		form               url.Values
		expectedReturnCode int
		expectedReturn     models.Introspection
	}{
		{
			name:               "Bad Type",
			form:               url.Values{"token": {"34534"}},
			expectedReturnCode: http.StatusBadRequest,
		},
		{
			name:               "No Token",
			header:             map[string][]string{"Content-Type": {"application/x-www-form-urlencoded"}},
			expectedReturnCode: http.StatusBadRequest,
		},
		{
			name:               "Expired",
			header:             map[string][]string{"Content-Type": {"application/x-www-form-urlencoded"}},
			form:               url.Values{"token": {"34534"}},
			expectedReturnCode: http.StatusOK,
			expectedReturn: models.Introspection{
				Active: false,
			},
		},
		{
			name:   "Success",
			header: map[string][]string{"Content-Type": {"application/x-www-form-urlencoded"}},
			form:   url.Values{"token": {tokenString}},
			fields: fields{
				KeySet: [2]Key{{KID: "k1", PrivateKey: privKey}, {KID: "k2", PrivateKey: nil}},
				accounts: []*ServiceAccount{
					{Config: &ServiceAccountConfig{Name: "sa1"}},
				},
				discoveryConfig: &models.DiscoveryConfig{
					Issuer: "issuer-string",
				},
			},
			expectedReturnCode: http.StatusOK,
			expectedReturn: models.Introspection{
				Active:    true,
				Scope:     "a.b.c c.d.e",
				ClientId:  "sa1",
				ExpiresAt: expire.Unix(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			realm := &Realm{
				Config:              tt.fields.Config,
				BaseURL:             tt.fields.BaseURL,
				KeySet:              tt.fields.KeySet,
				accounts:            tt.fields.accounts,
				claimsMap:           tt.fields.claimsMap,
				discoveryConfig:     tt.fields.discoveryConfig,
				discoveryConfigJson: tt.fields.discoveryConfigJson,
				jwks:                tt.fields.jwks,
			}
			request := &http.Request{
				Header: tt.header,
				Form:   tt.form,
			}
			response := httptest.NewRecorder()

			realm.serveIntrospection(response, request)
			if response.Result().StatusCode != tt.expectedReturnCode {
				t.Fatalf("Return code %d did not match expected %d with result %s", response.Result().StatusCode, tt.expectedReturnCode, string(response.Body.Bytes()))
			}
			intro := models.Introspection{}
			json.Unmarshal(response.Body.Bytes(), &intro)
			if intro != tt.expectedReturn {
				t.Fatalf("Return of %+v did not match expected %+v", intro, tt.expectedReturn)
			}
		})
	}
}
