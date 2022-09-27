package serverconfig

import (
	"io/ioutil"

	"pkgs/realmserver"

	"gopkg.in/yaml.v2"
)

type HostConfig struct {
	Scheme string `yaml:"scheme"`
	Host   string `yaml:"host"`
	Path   string `yaml:"path"`
}

type ServerConfig struct {
	ListenAddress string                    `yaml:"listenAddress"`
	ServerURI     HostConfig                `yaml:"serverURI"`
	Realms        []realmserver.RealmConfig `yaml:"realms"`
}

func LoadServerConfigFromFile(configPath string) (*ServerConfig, error) {
	config, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	return LoadServerConfig(config)
}

func LoadServerConfig(config []byte) (*ServerConfig, error) {
	sc := ServerConfig{}
	err := yaml.Unmarshal(config, &sc)
	if err != nil {
		return nil, err
	}
	return &sc, nil
}
