package aggregates_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/domain/aggregates"
	"github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/domain/domainerrors"
	vo "github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/domain/valueobjects"
)

func mustUserName(t *testing.T, s string) vo.UserName {
	t.Helper()
	name, err := vo.ParseUserName(s)
	require.NoError(t, err)
	return name
}

func mustHashedPassword(t *testing.T, password string) vo.HashedPassword {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	require.NoError(t, err)
	hashed, err := vo.ParseHashedPassword(string(h))
	require.NoError(t, err)
	return hashed
}

func mustUserID(t *testing.T, s string) vo.UserID {
	t.Helper()
	id, err := vo.ParseUserID(s)
	require.NoError(t, err)
	return id
}

func TestUser(t *testing.T) {
	t.Run("NewUser", func(t *testing.T) {
		t.Run("Happy path", func(t *testing.T) {
			t.Run("Create a user with a new ID", func(t *testing.T) {
				name := mustUserName(t, "admin")
				password := mustHashedPassword(t, "secret")

				user, err := aggregates.NewUser(name, password)

				require.NoError(t, err)
				assert.False(t, user.ID().Equals(vo.UserID{}), "ID must be generated")
				assert.True(t, user.Name().Equals(name))
				assert.True(t, user.Password().Equals(password))
			})

			t.Run("Generate a different ID for each user", func(t *testing.T) {
				name := mustUserName(t, "admin")
				password := mustHashedPassword(t, "secret")

				u1, err := aggregates.NewUser(name, password)
				require.NoError(t, err)
				u2, err := aggregates.NewUser(name, password)
				require.NoError(t, err)

				assert.False(t, u1.ID().Equals(u2.ID()))
			})
		})

		t.Run("Unhappy path", func(t *testing.T) {
			tests := []struct {
				name     string
				userName vo.UserName
				password vo.HashedPassword
			}{
				{name: "Zero UserName", userName: vo.UserName{}, password: mustHashedPassword(t, "secret")},
				{name: "Zero HashedPassword", userName: mustUserName(t, "admin"), password: vo.HashedPassword{}},
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					user, err := aggregates.NewUser(tt.userName, tt.password)

					assert.ErrorIs(t, err, domainerrors.ErrInvalidUser)
					assert.Zero(t, user)
				})
			}
		})
	})

	t.Run("RestoreUser", func(t *testing.T) {
		t.Run("Happy path", func(t *testing.T) {
			t.Run("Keep the given ID", func(t *testing.T) {
				id := mustUserID(t, "550e8400-e29b-41d4-a716-446655440000")
				name := mustUserName(t, "admin")
				password := mustHashedPassword(t, "secret")

				user, err := aggregates.RestoreUser(id, name, password)

				require.NoError(t, err)
				assert.True(t, user.ID().Equals(id))
				assert.True(t, user.Name().Equals(name))
				assert.True(t, user.Password().Equals(password))
			})
		})

		t.Run("Unhappy path", func(t *testing.T) {
			id := mustUserID(t, "550e8400-e29b-41d4-a716-446655440000")
			name := mustUserName(t, "admin")
			password := mustHashedPassword(t, "secret")

			tests := []struct {
				name     string
				id       vo.UserID
				userName vo.UserName
				password vo.HashedPassword
			}{
				{name: "Zero UserID", id: vo.UserID{}, userName: name, password: password},
				{name: "Zero UserName", id: id, userName: vo.UserName{}, password: password},
				{name: "Zero HashedPassword", id: id, userName: name, password: vo.HashedPassword{}},
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					user, err := aggregates.RestoreUser(tt.id, tt.userName, tt.password)

					assert.ErrorIs(t, err, domainerrors.ErrInvalidUser)
					assert.Zero(t, user)
				})
			}
		})
	})

	t.Run("Equals", func(t *testing.T) {
		id := mustUserID(t, "550e8400-e29b-41d4-a716-446655440000")
		otherID := mustUserID(t, "550e8400-e29b-41d4-a716-446655440001")

		t.Run("Happy path", func(t *testing.T) {
			t.Run("Users with the same ID are equal even with different attributes", func(t *testing.T) {
				u1, err := aggregates.RestoreUser(id, mustUserName(t, "admin"), mustHashedPassword(t, "a"))
				require.NoError(t, err)
				u2, err := aggregates.RestoreUser(id, mustUserName(t, "root"), mustHashedPassword(t, "b"))
				require.NoError(t, err)

				assert.True(t, u1.Equals(u2))
			})
		})

		t.Run("Unhappy path", func(t *testing.T) {
			t.Run("Users with different IDs are not equal even with same attributes", func(t *testing.T) {
				name := mustUserName(t, "admin")
				password := mustHashedPassword(t, "secret")
				u1, err := aggregates.RestoreUser(id, name, password)
				require.NoError(t, err)
				u2, err := aggregates.RestoreUser(otherID, name, password)
				require.NoError(t, err)

				assert.False(t, u1.Equals(u2))
			})
		})
	})
}
