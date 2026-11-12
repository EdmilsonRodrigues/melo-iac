package service_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/domain/aggregates"
	"github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/domain/domainerrors"
	vo "github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/domain/valueobjects"
	"github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/service"
)

const ttl = time.Hour

type env struct {
	svc    *service.AuthService
	user   aggregates.User
	users  *fakeUsers
	tokens *fakeTokens
	clock  *fakeClock
}

type spyHasher struct {
	calls int
	inner service.BcryptHasher
}

func newEnv(t *testing.T) env {
	t.Helper()

	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	require.NoError(t, err)
	name, err := vo.ParseUserName("admin")
	require.NoError(t, err)
	hashed, err := vo.ParseHashedPassword(string(hash))
	require.NoError(t, err)
	user, err := aggregates.NewUser(name, hashed)
	require.NoError(t, err)

	users := newFakeUsers(user)
	tokens := newFakeTokens()
	clock := &fakeClock{now: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)}

	return env{
		svc:    service.NewAuthService(users, tokens, clock, service.BcryptHasher{}, ttl),
		user:   user,
		users:  users,
		tokens: tokens,
		clock:  clock,
	}
}

func (h *spyHasher) Compare(hash vo.HashedPassword, password vo.RawPassword) error {
	h.calls++
	return h.inner.Compare(hash, password)
}

func TestAuth(t *testing.T) {
	t.Run("Login user successfully", func(t *testing.T) {
		e := newEnv(t)
		ctx := context.Background()

		token, err := e.svc.Login(ctx, "admin", "secret")

		require.NoError(t, err)
		assert.NotEmpty(t, token)

		saved, err := e.tokens.FindByValue(ctx, token)
		require.NoError(t, err, "returned token must have been saved")
		assert.True(t, saved.UserID().Equals(e.user.ID()), "token must reference the user by ID")
		assert.Equal(t, e.clock.now.Add(ttl), saved.ExpiresAt())
	})

	t.Run("Login Token are Unique", func(t *testing.T) {
		e := newEnv(t)
		ctx := context.Background()

		a, err := e.svc.Login(ctx, "admin", "secret")
		require.NoError(t, err)
		b, err := e.svc.Login(ctx, "admin", "secret")
		require.NoError(t, err)

		assert.NotEqual(t, a, b)
	})

	t.Run("Login user with invalid credentials", func(t *testing.T) {
		tests := []struct {
			name, username, password string
		}{
			{name: "Wrong password", username: "admin", password: "wrong"},
			{name: "Empty password", username: "admin", password: ""},
			{name: "Password longer than 72 bytes", username: "admin", password: strings.Repeat("a", 73)},
			{name: "Unknown user", username: "ghost", password: "secret"},
			{name: "Invalid user name", username: "a", password: "secret"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				e := newEnv(t)

				token, err := e.svc.Login(context.Background(), tt.username, tt.password)

				assert.ErrorIs(t, err, domainerrors.ErrInvalidCredentials)
				assert.Empty(t, token)
				assert.Empty(t, e.tokens.tokens, "no token may be saved")
			})
		}
	})

	t.Run("Login user with storage error", func(t *testing.T) {
		e := newEnv(t)
		boom := errors.New("cluster down")
		e.users.err = boom

		token, err := e.svc.Login(context.Background(), "admin", "secret")

		assert.ErrorIs(t, err, boom)
		assert.NotErrorIs(t, err, domainerrors.ErrInvalidCredentials, "infra failure must not look like a 401")
		assert.Empty(t, token)
	})

	t.Run("Login SaveFailure", func(t *testing.T) {
		e := newEnv(t)
		boom := errors.New("cannot write secret")
		e.tokens.err = boom

		token, err := e.svc.Login(context.Background(), "admin", "secret")

		assert.ErrorIs(t, err, boom)
		assert.Empty(t, token, "never return a token that was not saved")
	})

	t.Run("Login UnknownUserStillRunsHasher", func(t *testing.T) {
		e := newEnv(t)
		spy := &spyHasher{}
		svc := service.NewAuthService(e.users, e.tokens, e.clock, spy, ttl)

		_, err := svc.Login(context.Background(), "ghost", "secret")

		assert.ErrorIs(t, err, domainerrors.ErrInvalidCredentials)
		assert.Equal(t, 1, spy.calls, "hasher must run even when the user does not exist")
	})

	t.Run("Logout revokes the token", func(t *testing.T) {
		e := newEnv(t)
		ctx := context.Background()
		token, err := e.svc.Login(ctx, "admin", "secret")
		require.NoError(t, err)

		err = e.svc.Logout(ctx, token)

		require.NoError(t, err)
		_, err = e.tokens.FindByValue(ctx, token)
		assert.ErrorIs(t, err, domainerrors.ErrInvalidToken)
	})

	t.Run("Logout unknown token is not an error", func(t *testing.T) {
		e := newEnv(t)

		err := e.svc.Logout(context.Background(), "unknown")

		assert.NoError(t, err)
	})

	t.Run("Logout propagates storage error", func(t *testing.T) {
		e := newEnv(t)
		boom := errors.New("cannot delete secret")
		e.tokens.revokeErr = boom

		err := e.svc.Logout(context.Background(), "any")

		assert.ErrorIs(t, err, boom)
	})

	t.Run("Validate valid token returns the user ID", func(t *testing.T) {
		e := newEnv(t)
		ctx := context.Background()
		token, err := e.svc.Login(ctx, "admin", "secret")
		require.NoError(t, err)

		userID, err := e.svc.Validate(ctx, token)

		require.NoError(t, err)
		assert.True(t, userID.Equals(e.user.ID()))
	})

	t.Run("Validate invalid tokens", func(t *testing.T) {
		tests := []struct {
			name  string
			setup func(e env) string
		}{
			{"unknown", func(e env) string { return "nope" }},
			{"empty", func(e env) string { return "" }},
			{"revoked", func(e env) string {
				tok, _ := e.svc.Login(context.Background(), "admin", "secret")
				_ = e.svc.Logout(context.Background(), tok)
				return tok
			}},
			{"expired", func(e env) string {
				tok, _ := e.svc.Login(context.Background(), "admin", "secret")
				e.clock.now = e.clock.now.Add(ttl) // exatamente na expiracao
				return tok
			}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				e := newEnv(t)
				token := tt.setup(e)

				userID, err := e.svc.Validate(context.Background(), token)

				assert.ErrorIs(t, err, domainerrors.ErrInvalidToken)
				assert.Zero(t, userID)
			})
		}
	})

	t.Run("Validate propagates storage error", func(t *testing.T) {
		e := newEnv(t)
		boom := errors.New("cluster down")
		e.tokens.findErr = boom

		userID, err := e.svc.Validate(context.Background(), "any")

		assert.ErrorIs(t, err, boom)
		assert.NotErrorIs(t, err, domainerrors.ErrInvalidToken, "infra failure must not look like an invalid token")
		assert.Zero(t, userID)
	})
}
