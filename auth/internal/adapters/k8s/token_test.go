package k8s_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/EdmilsonRodrigues/melo-iac/auth/internal/adapters/k8s"
	"github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/domain/aggregates"
	"github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/domain/domainerrors"
)

func TestTokenRepository(t *testing.T) {
	exp := time.Date(2026, 10, 2, 13, 0, 0, 0, time.UTC)
	userID := mustUserID(t, "550e8400-e29b-41d4-a716-446655440000")
	tok, err := aggregates.NewToken("abc123", userID, exp)
	require.NoError(t, err)

	t.Run("Save then find returns the token", func(t *testing.T) {
		ctx := context.Background()
		repo := k8s.NewTokenRepository(fake.NewSimpleClientset(), testNamespace)
		require.NoError(t, repo.Save(ctx, tok))

		got, err := repo.FindByValue(ctx, "abc123")

		require.NoError(t, err)
		assert.Equal(t, tok.Value(), got.Value())
		assert.True(t, tok.UserID().Equals(got.UserID()))
		assert.True(t, tok.ExpiresAt().Equal(got.ExpiresAt()))
	})

	t.Run("Find unknown token returns ErrInvalidToken", func(t *testing.T) {
		repo := k8s.NewTokenRepository(fake.NewSimpleClientset(), testNamespace)

		_, err := repo.FindByValue(context.Background(), "nope")

		assert.ErrorIs(t, err, domainerrors.ErrInvalidToken)
	})

	t.Run("Revoke removes the token", func(t *testing.T) {
		ctx := context.Background()
		repo := k8s.NewTokenRepository(fake.NewSimpleClientset(), testNamespace)
		require.NoError(t, repo.Save(ctx, tok))

		require.NoError(t, repo.Revoke(ctx, "abc123"))

		_, err := repo.FindByValue(ctx, "abc123")
		assert.ErrorIs(t, err, domainerrors.ErrInvalidToken)
	})

	t.Run("Revoke unknown token is not an error", func(t *testing.T) {
		repo := k8s.NewTokenRepository(fake.NewSimpleClientset(), testNamespace)

		assert.NoError(t, repo.Revoke(context.Background(), "nope"))
	})

	t.Run("Token value is never stored in the cluster", func(t *testing.T) {
		ctx := context.Background()
		client := fake.NewSimpleClientset()
		repo := k8s.NewTokenRepository(client, testNamespace)
		require.NoError(t, repo.Save(ctx, tok))

		list, err := client.CoreV1().Secrets(testNamespace).List(ctx, metav1.ListOptions{})
		require.NoError(t, err)
		require.Len(t, list.Items, 1)

		s := list.Items[0]
		assert.NotContains(t, s.Name, "abc123")
		for k, v := range s.Data {
			assert.NotContains(t, string(v), "abc123", "key %s leaks the token", k)
		}
	})
	t.Run("Corrupted token secrets are an error, not ErrInvalidToken", func(t *testing.T) {
		tests := []struct {
			name   string
			mutate func(d map[string][]byte)
		}{
			{"missing userID", func(d map[string][]byte) { delete(d, "userID") }},
			{"invalid userID", func(d map[string][]byte) { d["userID"] = []byte("not-a-uuid") }},
			{"invalid expiresAt", func(d map[string][]byte) { d["expiresAt"] = []byte("tomorrow") }},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				ctx := context.Background()
				client := fake.NewSimpleClientset()
				repo := k8s.NewTokenRepository(client, testNamespace)
				require.NoError(t, repo.Save(ctx, tok))
				overwriteOnlySecretData(t, client, tt.mutate)

				_, err := repo.FindByValue(ctx, "abc123")

				require.Error(t, err)
				assert.NotErrorIs(t, err, domainerrors.ErrInvalidToken)
			})
		}
	})
}
