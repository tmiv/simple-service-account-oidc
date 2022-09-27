package main

import (
	"fmt"
	"log"
	"os"

	"net/http"
	"net/url"

	"pkgs/healthcheck"
	"pkgs/notfound"
	"pkgs/realmserver"
	"pkgs/serverconfig"

	"github.com/gorilla/mux"
)

func main() {
	fmt.Printf("Startup\n")
	configPath := os.Getenv("CONFIG_PATH")
	if len(configPath) == 0 {
		configPath = "/srv/data/config.yaml"
	}
	config, err := serverconfig.LoadServerConfigFromFile(configPath)
	if err != nil {
		log.Fatalf("Could not load config from %s : %v\n", configPath, err)
	}

	r := mux.NewRouter()
	healthcheck.AddHealthcheck(r)

	realms := make([]*realmserver.Realm, len(config.Realms))

	base_uri := url.URL{Scheme: config.ServerURI.Scheme, Path: config.ServerURI.Path, Host: config.ServerURI.Host}
	for i, realmConfig := range config.Realms {
		realm, err := realmserver.CreateRealm(&realmConfig, base_uri, r)
		if err != nil {
			log.Fatalf("Error setting up realm %s: %v", realmConfig.Name, err)
		}
		realms[i] = realm
	}

	r.NotFoundHandler = r.NewRoute().HandlerFunc(notfound.ServeNotFound).GetHandler()
	fmt.Printf("Listening at %s\n", config.ListenAddress)
	if err = http.ListenAndServe(config.ListenAddress, r); err != nil && err != http.ErrServerClosed {
		log.Fatalf("listen:%+s\n", err)
	}
}
