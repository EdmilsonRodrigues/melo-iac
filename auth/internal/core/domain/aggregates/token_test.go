package aggregates_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/domain/aggregates"
	"github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/domain/domainerrors"
	vo "github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/domain/valueobjects"
)

func TestToken(t *testing.T) {
	userID := mustUserID(t, "550e8400-e29b-41d4-a716-446655440000")
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	exp := now.Add(time.Hour)

	t.Run("NewToken", func(t *testing.T) {
		t.Run("Happy path", func(t *testing.T) {
			t.Run("Create a valid token", func(t *testing.T) {
				tok, err := aggregates.NewToken("token", userID, exp)

				require.NoError(t, err)
				assert.Equal(t, "token", tok.Value())
				assert.True(t, tok.UserID().Equals(userID))
				assert.Equal(t, exp, tok.ExpiresAt())
			})
		})

		t.Run("Unhappy path", func(t *testing.T) {
			tests := []struct {
				name      string
				value     string
				userID    vo.UserID
				expiresAt time.Time
			}{
				{name: "Empty Value", value: "", userID: userID, expiresAt: exp},
				{name: "Zero UserID", value: "token", userID: vo.UserID{}, expiresAt: exp},
				{name: "Zero ExpiresAt", value: "token", userID: userID, expiresAt: time.Time{}},
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					tok, err := aggregates.NewToken(tt.value, tt.userID, tt.expiresAt)

					assert.ErrorIs(t, err, domainerrors.ErrInvalidToken)
					assert.Zero(t, tok)
				})
			}
		})
	})

	t.Run("IsExpired", func(t *testing.T) {
		tok, err := aggregates.NewToken("token", userID, exp)
		require.NoError(t, err)

		t.Run("Happy path", func(t *testing.T) {
			t.Run("Not expired before expiration", func(t *testing.T) {
				assert.False(t, tok.IsExpired(now))
				assert.False(t, tok.IsExpired(exp.Add(-time.Nanosecond)))
			})
		})

		t.Run("Unhappy path", func(t *testing.T) {
			t.Run("Expired exactly at expiration", func(t *testing.T) {
				assert.True(t, tok.IsExpired(exp))
			})

			t.Run("Expired after expiration", func(t *testing.T) {
				assert.True(t, tok.IsExpired(exp.Add(time.Hour)))
			})
		})
	})

	t.Run("Equals", func(t *testing.T) {
		t.Run("Happy path", func(t *testing.T) {
			t.Run("Tokens with the same value are equal", func(t *testing.T) {
				t1, err := aggregates.NewToken("token", userID, exp)
				require.NoError(t, err)
				t2, err := aggregates.NewToken("token", userID, exp.Add(time.Hour))
				require.NoError(t, err)

				assert.True(t, t1.Equals(t2))
			})
		})

		t.Run("Unhappy path", func(t *testing.T) {
			t.Run("Tokens with different values are not equal", func(t *testing.T) {
				t1, err := aggregates.NewToken("token-a", userID, exp)
				require.NoError(t, err)
				t2, err := aggregates.NewToken("token-b", userID, exp)
				require.NoError(t, err)

				assert.False(t, t1.Equals(t2))
			})
		})
	})
}
