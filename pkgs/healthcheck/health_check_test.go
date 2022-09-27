package healthcheck

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthCheck(t *testing.T) {
	request := &http.Request{}
	response := httptest.NewRecorder()

	healthCheckHandler(response, request)

	if response.Code != http.StatusOK {
		t.Fail()
	}
}
