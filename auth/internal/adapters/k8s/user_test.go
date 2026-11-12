package k8s_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/EdmilsonRodrigues/melo-iac/auth/internal/adapters/k8s"
	"github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/domain/aggregates"
	"github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/domain/domainerrors"
	vo "github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/domain/valueobjects"
)

const testNamespace = "melo-system"

func mustUserName(t *testing.T, s string) vo.UserName {
	t.Helper()
	name, err := vo.ParseUserName(s)
	require.NoError(t, err)
	return name
}

func mustUserID(t *testing.T, s string) vo.UserID {
	t.Helper()
	id, err := vo.ParseUserID(s)
	require.NoError(t, err)
	return id
}

func mustUser(t *testing.T, name, password string) aggregates.User {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	require.NoError(t, err)
	hashed, err := vo.ParseHashedPassword(string(h))
	require.NoError(t, err)
	u, err := aggregates.NewUser(mustUserName(t, name), hashed)
	require.NoError(t, err)
	return u
}

func assertSameUser(t *testing.T, want, got aggregates.User) {
	t.Helper()
	assert.True(t, want.ID().Equals(got.ID()), "id")
	assert.True(t, want.Name().Equals(got.Name()), "name")
	assert.True(t, want.Password().Equals(got.Password()), "password")
}

func TestUserRepository(t *testing.T) {
	t.Run("Add then find returns the same user", func(t *testing.T) {
		ctx := context.Background()
		repo := k8s.NewUserRepository(fake.NewSimpleClientset(), testNamespace)
		want := mustUser(t, "admin", "secret")

		require.NoError(t, repo.Add(ctx, want))

		got, err := repo.FindByName(ctx, mustUserName(t, "admin"))
		require.NoError(t, err)
		assertSameUser(t, want, got)
	})

	t.Run("Find unknown user returns ErrUserNotFound", func(t *testing.T) {
		repo := k8s.NewUserRepository(fake.NewSimpleClientset(), testNamespace)

		_, err := repo.FindByName(context.Background(), mustUserName(t, "ghost"))

		assert.ErrorIs(t, err, domainerrors.ErrUserNotFound)
	})

	t.Run("Add duplicate returns ErrUserAlreadyExists and keeps the original", func(t *testing.T) {
		ctx := context.Background()
		repo := k8s.NewUserRepository(fake.NewSimpleClientset(), testNamespace)
		original := mustUser(t, "admin", "secret1")
		require.NoError(t, repo.Add(ctx, original))

		err := repo.Add(ctx, mustUser(t, "admin", "secret2"))

		assert.ErrorIs(t, err, domainerrors.ErrUserAlreadyExists)
		got, err := repo.FindByName(ctx, mustUserName(t, "admin"))
		require.NoError(t, err)
		assertSameUser(t, original, got)
	})

	t.Run("User name with characters invalid for a Secret name works", func(t *testing.T) {
		ctx := context.Background()
		repo := k8s.NewUserRepository(fake.NewSimpleClientset(), testNamespace)
		want := mustUser(t, "Admin@Melo.io", "secret")

		require.NoError(t, repo.Add(ctx, want))

		got, err := repo.FindByName(ctx, mustUserName(t, "Admin@Melo.io"))
		require.NoError(t, err)
		assertSameUser(t, want, got)
	})

	t.Run("Users are isolated by namespace", func(t *testing.T) {
		ctx := context.Background()
		client := fake.NewSimpleClientset()
		a := k8s.NewUserRepository(client, "ns-a")
		b := k8s.NewUserRepository(client, "ns-b")
		require.NoError(t, a.Add(ctx, mustUser(t, "admin", "secret")))

		_, err := b.FindByName(ctx, mustUserName(t, "admin"))

		assert.ErrorIs(t, err, domainerrors.ErrUserNotFound)
	})

	t.Run("Corrupted user secrets", func(t *testing.T) {
		valid := mustUser(t, "admin", "secret")

		tests := []struct {
			name   string
			mutate func(d map[string][]byte)
		}{
			{"missing userID", func(d map[string][]byte) { delete(d, "userID") }},
			{"invalid userID", func(d map[string][]byte) { d["userID"] = []byte("not-a-uuid") }},
			{"missing passwordHash", func(d map[string][]byte) { delete(d, "passwordHash") }},
			{"plain-text passwordHash", func(d map[string][]byte) { d["passwordHash"] = []byte("secret") }},
		}

		for _, tt := range tests {
			t.Run(tt.name+" is an error, not ErrUserNotFound", func(t *testing.T) {
				ctx := context.Background()
				client := fake.NewSimpleClientset()
				repo := k8s.NewUserRepository(client, testNamespace)
				require.NoError(t, repo.Add(ctx, valid))
				overwriteOnlySecretData(t, client, tt.mutate)

				_, err := repo.FindByName(ctx, mustUserName(t, "admin"))

				require.Error(t, err)
				assert.NotErrorIs(t, err, domainerrors.ErrUserNotFound)
				assert.NotContains(t, err.Error(), valid.Password().Value(), "hash must not leak")
			})
		}

		t.Run("stored user name differs from the requested one is ErrUserNotFound", func(t *testing.T) {
			ctx := context.Background()
			client := fake.NewSimpleClientset()
			repo := k8s.NewUserRepository(client, testNamespace)
			require.NoError(t, repo.Add(ctx, valid))
			overwriteOnlySecretData(t, client, func(d map[string][]byte) { d["username"] = []byte("root") })

			_, err := repo.FindByName(ctx, mustUserName(t, "admin"))

			assert.ErrorIs(t, err, domainerrors.ErrUserNotFound)
		})
	})
}

// overwriteOnlySecretData edits the single Secret in testNamespace,
// simulating a Secret changed by hand in the cluster.
func overwriteOnlySecretData(t *testing.T, client *fake.Clientset, mutate func(map[string][]byte)) {
	t.Helper()
	ctx := context.Background()
	secrets := client.CoreV1().Secrets(testNamespace)
	list, err := secrets.List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	require.Len(t, list.Items, 1)

	s := list.Items[0].DeepCopy()
	mutate(s.Data)
	_, err = secrets.Update(ctx, s, metav1.UpdateOptions{})
	require.NoError(t, err)
}
