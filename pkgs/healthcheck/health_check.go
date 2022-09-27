package healthcheck

import (
	"io"
	"net/http"

	"github.com/gorilla/mux"
)

func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, `{"alive": true}`)
}

func AddHealthcheck(router *mux.Router) {
	router.HandleFunc("/health", healthCheckHandler)
}
