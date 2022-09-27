package realmserver

import (
	"crypto/rand"
	"crypto/rsa"
	"net/url"
	"reflect"
	"testing"
	"time"

	"gopkg.in/yaml.v2"
)

func TestBasicRead(t *testing.T) {
	data := "name: hello\n" +
		"keySource: jwksFile\n" +
		"keySourceFilePath: /srv/data/publicKey.pem\n" +
		"scopes:\n" +
		"- noun.noun.verb1\n" +
		"- noun.noun.verb2"
	sac := ServiceAccountConfig{}

	err := yaml.Unmarshal([]byte(data), &sac)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if sac.Name != "hello" {
		t.Fatalf("Name is not equal to \"hello\"")
	}
	if sac.KeySourceFilePath != "/srv/data/publicKey.pem" {
		t.Fatalf("PublicKeyFilePath did not read correctly")
	}
	if len(sac.Scopes) != 2 {
		t.Fatalf("There should be two scopes")
	}
	if sac.Scopes[0] != "noun.noun.verb1" || sac.Scopes[1] != "noun.noun.verb2" {
		t.Fatalf("Scopes did not read correctly")
	}

	sa, err := CreateServiceAccount(&sac)
	if err != nil || sa == nil {
		t.Fatalf("Service account is not valid: %v", err)
	}
}

func TestBadServiceAccount(t *testing.T) {
	sac := ServiceAccountConfig{}
	sa, err := CreateServiceAccount(&sac)
	if sa != nil || err == nil {
		t.Fatalf("Service account failed to detect error")
	}
}

func TestCreateServiceAccount(t *testing.T) {
	type args struct {
		config *ServiceAccountConfig
	}
	goodURI, _ := url.ParseRequestURI("http://test.com/")
	goodConfig := &ServiceAccountConfig{
		Name:         "account",
		KeySource:    JWKSUri,
		KeySourceURI: goodURI.String(),
	}
	tests := []struct {
		name        string
		args        args
		want        *ServiceAccount
		wantErr     bool
		wantCompare bool
	}{
		{
			name: "Bad Keysource Type",
			args: args{
				config: &ServiceAccountConfig{
					Name: "account",
				},
			},
			wantErr:     true,
			wantCompare: false,
		},
		{
			name: "Bad Name",
			args: args{
				config: &ServiceAccountConfig{},
			},
			wantErr:     true,
			wantCompare: false,
		},
		{
			name: "Bad Keysource File Path",
			args: args{
				config: &ServiceAccountConfig{
					Name:      "account",
					KeySource: JWKSFile,
				},
			},
			wantErr:     true,
			wantCompare: false,
		},
		{
			name: "Bad Keysource URL",
			args: args{
				config: &ServiceAccountConfig{
					Name:         "account",
					KeySource:    JWKSUri,
					KeySourceURI: "&",
				},
			},
			wantErr:     true,
			wantCompare: false,
		},
		{
			name: "Good Keysource URL",
			args: args{
				config: goodConfig,
			},
			want: &ServiceAccount{
				Config:        goodConfig,
				cachedJWKSUri: goodURI,
				cachedKeys:    make(map[string]*rsa.PublicKey, 0),
			},
			wantErr:     false,
			wantCompare: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CreateServiceAccount(tt.args.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateServiceAccount() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantCompare && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CreateServiceAccount() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestKeySourceType_UnmarshalYAML(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		expected    KeySourceType
		wantErr     bool
		wantCompare bool
	}{
		{
			name:    "Bad input",
			input:   []byte("quack"),
			wantErr: true,
		},
		{
			name:        "Good File",
			input:       []byte("jwksFile"),
			expected:    JWKSFile,
			wantErr:     false,
			wantCompare: true,
		},
		{
			name:        "Good URI",
			input:       []byte("jwksUri"),
			expected:    JWKSUri,
			wantErr:     false,
			wantCompare: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ks KeySourceType
			err := yaml.Unmarshal([]byte(tt.input), &ks)
			if (err != nil) != tt.wantErr {
				t.Errorf("KeySourceType.UnmarshalYAML() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantCompare && tt.expected != ks {
				t.Errorf("KeySourceType.UnmarshalYAML() got = %v, want %v", ks, tt.expected)
			}
		})
	}
}

func TestServiceAccount_CheckJWT(t *testing.T) {
	type fields struct {
		exp     time.Time
		now     time.Time
		aud     string
		keyName string
		issuer  string
		subject string
		claims  map[string]interface{}
	}
	type args struct {
		expectedAud          string
		expectedKeyName      string
		serviceAccountConfig *ServiceAccountConfig
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "Expired",
			args: args{
				expectedAud:     "a",
				expectedKeyName: "k1",
				serviceAccountConfig: &ServiceAccountConfig{
					Name: "client-name",
				},
			},
			fields: fields{
				exp:     time.Unix(0, 0),
				now:     time.Now().UTC(),
				aud:     "a",
				keyName: "k1",
				issuer:  "client-name",
				subject: "client-name",
			},
			wantErr: true,
		},
		{
			name: "Not Ready",
			args: args{
				expectedAud:     "a",
				expectedKeyName: "k1",
				serviceAccountConfig: &ServiceAccountConfig{
					Name: "client-name",
				},
			},
			fields: fields{
				exp:     time.Now().Add(time.Hour * time.Duration(24)).UTC(),
				now:     time.Now().Add(time.Hour * time.Duration(4)).UTC(),
				aud:     "a",
				keyName: "k1",
				issuer:  "client-name",
				subject: "client-name",
			},
			wantErr: true,
		},
		{
			name: "Key not found",
			args: args{
				expectedAud:     "a",
				expectedKeyName: "k2",
				serviceAccountConfig: &ServiceAccountConfig{
					Name: "client-name",
				},
			},
			fields: fields{
				exp:     time.Now().Add(time.Hour * time.Duration(24)).UTC(),
				now:     time.Now().Add(time.Hour * time.Duration(4)).UTC(),
				aud:     "a",
				keyName: "k1",
				issuer:  "client-name",
				subject: "client-name",
			},
			wantErr: true,
		},
		{
			name: "Bad Audience",
			args: args{
				expectedAud:     "b",
				expectedKeyName: "k1",
				serviceAccountConfig: &ServiceAccountConfig{
					Name: "client-name",
				},
			},
			fields: fields{
				exp:     time.Now().Add(time.Hour * time.Duration(24)).UTC(),
				now:     time.Now().UTC(),
				aud:     "a",
				keyName: "k1",
				issuer:  "client-name",
				subject: "client-name",
			},
			wantErr: true,
		},
		{
			name: "Bad Subject",
			args: args{
				expectedAud:     "b",
				expectedKeyName: "k1",
				serviceAccountConfig: &ServiceAccountConfig{
					Name: "client-name",
				},
			},
			fields: fields{
				exp:     time.Now().Add(time.Hour * time.Duration(24)).UTC(),
				now:     time.Now().UTC(),
				aud:     "a",
				keyName: "k1",
				issuer:  "client-name",
				subject: "name",
			},
			wantErr: true,
		},
		{
			name: "Bad Issuer",
			args: args{
				expectedAud:     "a",
				expectedKeyName: "k1",
				serviceAccountConfig: &ServiceAccountConfig{
					Name: "client-name",
				},
			},
			fields: fields{
				exp:     time.Now().Add(time.Hour * time.Duration(24)).UTC(),
				now:     time.Now().UTC(),
				aud:     "a",
				keyName: "k1",
				issuer:  "name",
				subject: "client-name",
			},
			wantErr: true,
		},
		{
			name: "Good",
			args: args{
				expectedAud:     "a",
				expectedKeyName: "k1",
				serviceAccountConfig: &ServiceAccountConfig{
					Name: "client-name",
				},
			},
			fields: fields{
				exp:     time.Now().Add(time.Hour * time.Duration(24)).UTC(),
				now:     time.Now().UTC(),
				aud:     "a",
				keyName: "k1",
				issuer:  "client-name",
				subject: "client-name",
			},
			wantErr: false,
		},
	}
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sa := &ServiceAccount{
				cachedKeys: map[string]*rsa.PublicKey{tt.args.expectedKeyName: &privKey.PublicKey},
				Config:     tt.args.serviceAccountConfig,
			}

			tokenString, err := buildJWT(privKey, tt.fields.claims, tt.fields.aud, tt.fields.issuer, tt.fields.subject, tt.fields.keyName, tt.fields.now, tt.fields.exp)
			_, err = sa.CheckJWT(tokenString, tt.args.expectedAud)
			if (err != nil) != tt.wantErr {
				t.Errorf("ServiceAccount.CheckJWT() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
