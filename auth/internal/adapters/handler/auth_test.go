package handler_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/EdmilsonRodrigues/melo-iac/auth/internal/adapters/handler"
	"github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/domain/domainerrors"
	vo "github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/domain/valueobjects"
)

type fakeUseCase struct {
	loginToken string
	loginErr   error
	logoutErr  error

	gotUsername, gotPassword string
	gotLogoutToken           string
	logoutCalls              int
}

func (f *fakeUseCase) Login(_ context.Context, username, password string) (string, error) {
	f.gotUsername, f.gotPassword = username, password
	return f.loginToken, f.loginErr
}

func (f *fakeUseCase) Logout(_ context.Context, token string) error {
	f.logoutCalls++
	f.gotLogoutToken = token
	return f.logoutErr
}

func (f *fakeUseCase) Validate(_ context.Context, _ string) (vo.UserID, error) {
	return vo.UserID{}, errors.New("not used by the handler")
}

func do(h http.Handler, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

const (
	loginPath  = "/api/v1/auth/login"
	logoutPath = "/api/v1/auth/logout"
)

func TestHandler(t *testing.T) {
	t.Run("Login success", func(t *testing.T) {
		uc := &fakeUseCase{loginToken: "abc123"}
		h := handler.NewAuthHandler(uc).Routes()

		rec := do(h, http.MethodPost, loginPath, `{"username":"admin","password":"secret"}`, nil)

		require.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Header().Get("Content-Type"), "application/json")
		assert.JSONEq(t, `{"token":"abc123"}`, rec.Body.String())
		assert.Equal(t, "admin", uc.gotUsername)
		assert.Equal(t, "secret", uc.gotPassword)
	})

	t.Run("Login bad requests", func(t *testing.T) {
		tests := []struct{ name, body string }{
			{"invalid json", `not json`},
			{"empty body", ``},
			{"missing password", `{"username":"admin"}`},
			{"missing username", `{"password":"secret"}`},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				uc := &fakeUseCase{loginToken: "abc123"}
				h := handler.NewAuthHandler(uc).Routes()

				rec := do(h, http.MethodPost, loginPath, tt.body, nil)

				assert.Equal(t, http.StatusBadRequest, rec.Code)
				assert.Empty(t, uc.gotUsername, "use case must not be called")
			})
		}
	})

	t.Run("Login invalid credentials is 401", func(t *testing.T) {
		uc := &fakeUseCase{loginErr: domainerrors.ErrInvalidCredentials}
		h := handler.NewAuthHandler(uc).Routes()

		rec := do(h, http.MethodPost, loginPath, `{"username":"admin","password":"wrong"}`, nil)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.NotContains(t, rec.Body.String(), "token")
	})

	t.Run("Login infrastructure error is 500 and hides details", func(t *testing.T) {
		uc := &fakeUseCase{loginErr: errors.New("secret melo-system/user-9f3 forbidden")}
		h := handler.NewAuthHandler(uc).Routes()

		rec := do(h, http.MethodPost, loginPath, `{"username":"admin","password":"secret"}`, nil)

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		assert.NotContains(t, rec.Body.String(), "melo-system", "internal details must not leak")
	})

	t.Run("Login wrong method is 405", func(t *testing.T) {
		h := handler.NewAuthHandler(&fakeUseCase{}).Routes()

		rec := do(h, http.MethodGet, loginPath, "", nil)

		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	})

	t.Run("Logout success is 204", func(t *testing.T) {
		uc := &fakeUseCase{}
		h := handler.NewAuthHandler(uc).Routes()

		rec := do(h, http.MethodPost, logoutPath, "", map[string]string{"Authorization": "Bearer abc123"})

		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.Equal(t, "abc123", uc.gotLogoutToken)
	})

	t.Run("Logout missing or malformed header is 401", func(t *testing.T) {
		tests := []struct {
			name    string
			headers map[string]string
		}{
			{"no header", nil},
			{"wrong scheme", map[string]string{"Authorization": "Basic abc"}},
			{"empty bearer", map[string]string{"Authorization": "Bearer "}},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				uc := &fakeUseCase{}
				h := handler.NewAuthHandler(uc).Routes()

				rec := do(h, http.MethodPost, logoutPath, "", tt.headers)

				assert.Equal(t, http.StatusUnauthorized, rec.Code)
				assert.Zero(t, uc.logoutCalls, "use case must not be called")
			})
		}
	})

	t.Run("Logout infrastructure error is 500", func(t *testing.T) {
		uc := &fakeUseCase{logoutErr: errors.New("cluster down")}
		h := handler.NewAuthHandler(uc).Routes()

		rec := do(h, http.MethodPost, logoutPath, "", map[string]string{"Authorization": "Bearer abc123"})

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}
