package httpapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
)

func TestRespondErr_RedactsUnmappedInternalErrors(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/login", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Response().Header().Set(echo.HeaderXRequestID, "test-request-id")

	rawErr := errors.New(`connect to LDAP server: dial tcp 127.0.0.1:3394: connect: connection refused`)
	if err := respondErr(c, rawErr); err != nil {
		t.Fatalf("respondErr: %v", err)
	}

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	body := rec.Body.String()
	if strings.Contains(body, "3394") || strings.Contains(body, "dial tcp") {
		t.Errorf("body leaked internal error detail: %s", body)
	}
	if !strings.Contains(body, "test-request-id") {
		t.Errorf("body = %s, want it to carry the request ID for log correlation", body)
	}
}

func TestRespondErr_MappedDomainErrorsPassThroughVerbatim(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{"not found", domain.ErrNotFound, http.StatusNotFound},
		{"already exists", domain.ErrAlreadyExists, http.StatusConflict},
		{"invalid credentials", domain.ErrInvalidCredentials, http.StatusUnauthorized},
		{"permission denied", domain.ErrPermissionDenied, http.StatusForbidden},
		{"invalid input", domain.ErrInvalidInput, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()
			req := httptest.NewRequest(http.MethodPost, "/api/users", nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			if err := respondErr(c, tc.err); err != nil {
				t.Fatalf("respondErr: %v", err)
			}
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if !strings.Contains(rec.Body.String(), tc.err.Error()) {
				t.Errorf("body = %s, want it to contain %q", rec.Body.String(), tc.err.Error())
			}
		})
	}
}
