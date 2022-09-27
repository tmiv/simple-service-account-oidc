package notfound

import (
	"fmt"
	"net/http"
)

func ServeNotFound(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Not Found %s from %s", r.RequestURI, r.RemoteAddr)
	w.WriteHeader(http.StatusNotFound)
}
