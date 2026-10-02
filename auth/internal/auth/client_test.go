package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newServer(t *testing.T, status int, body string) (*httptest.Server, *http.Request) {
	t.Helper()
	var got http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = *r.Clone(r.Context())
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

func TestClient_Login(t *testing.T) {
	t.Run("success returns the token", func(t *testing.T) {
		srv, req := newServer(t, http.StatusOK, `{"token":"abc"}`)
		c := auth.NewClient(srv.URL)

		token, err := c.Login(context.Background(), "john", "secret")

		require.NoError(t, err)
		assert.Equal(t, "abc", token)
		assert.Equal(t, http.MethodPost, req.Method)
		assert.Equal(t, "/api/v1/auth/login", req.URL.Path)
	})

	t.Run("unauthorized", func(t *testing.T) {
		srv, _ := newServer(t, http.StatusUnauthorized, `{}`)
		c := auth.NewClient(srv.URL)

		token, err := c.Login(context.Background(), "john", "wrong")

		assert.ErrorIs(t, err, auth.ErrInvalidCredentials)
		assert.Empty(t, token)
	})

	t.Run("empty token is an error", func(t *testing.T) {
		srv, _ := newServer(t, http.StatusOK, `{"token":""}`)
		c := auth.NewClient(srv.URL)

		_, err := c.Login(context.Background(), "john", "secret")

		assert.Error(t, err)
	})

	t.Run("invalid json is an error", func(t *testing.T) {
		srv, _ := newServer(t, http.StatusOK, `not json`)
		c := auth.NewClient(srv.URL)

		_, err := c.Login(context.Background(), "john", "secret")

		assert.Error(t, err)
	})

	t.Run("server error is not invalid credentials", func(t *testing.T) {
		srv, _ := newServer(t, http.StatusInternalServerError, `{}`)
		c := auth.NewClient(srv.URL)

		_, err := c.Login(context.Background(), "john", "secret")

		require.Error(t, err)
		assert.NotErrorIs(t, err, auth.ErrInvalidCredentials)
	})
}
