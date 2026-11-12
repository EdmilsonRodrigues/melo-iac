package valueobjects_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	vo "github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/domain/valueobjects"
)

func bcryptHash(t *testing.T, password string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	require.NoError(t, err)
	return string(h)
}

func TestHashedPassword(t *testing.T) {
	t.Run("Parse", func(t *testing.T) {
		t.Run("Happy path", func(t *testing.T) {
			t.Run("Parse a valid bcrypt hash", func(t *testing.T) {
				h := bcryptHash(t, "secret")
				hashed, err := vo.ParseHashedPassword(h)
				require.NoError(t, err)
				assert.Equal(t, h, hashed.Value())
			})
		})

		t.Run("Unhappy path", func(t *testing.T) {
			t.Run("Return error when string is empty", func(t *testing.T) {
				_, err := vo.ParseHashedPassword("")
				require.Error(t, err)
				assert.Contains(t, err.Error(), "invalid hashed password")
			})

			t.Run("Return error when string is not a bcrypt hash", func(t *testing.T) {
				_, err := vo.ParseHashedPassword("secret")
				require.Error(t, err)
				assert.Contains(t, err.Error(), "invalid hashed password")
			})

			t.Run("Return error when bcrypt hash is truncated", func(t *testing.T) {
				h := bcryptHash(t, "secret")
				_, err := vo.ParseHashedPassword(h[:len(h)-10])
				require.Error(t, err)
			})

			t.Run("Error message never contains the input", func(t *testing.T) {
				_, err := vo.ParseHashedPassword("my-plain-secret")
				require.Error(t, err)
				assert.NotContains(t, err.Error(), "my-plain-secret")
			})
		})
	})

	t.Run("Value", func(t *testing.T) {
		t.Run("Unhappy path", func(t *testing.T) {
			t.Run("Return empty string for zero value HashedPassword", func(t *testing.T) {
				var hashed vo.HashedPassword
				assert.Empty(t, hashed.Value())
			})
		})
	})

	t.Run("Equals", func(t *testing.T) {
		t.Run("Happy path", func(t *testing.T) {
			t.Run("Return true for the same hash", func(t *testing.T) {
				h := bcryptHash(t, "secret")
				h1, err := vo.ParseHashedPassword(h)
				require.NoError(t, err)
				h2, err := vo.ParseHashedPassword(h)
				require.NoError(t, err)
				assert.True(t, h1.Equals(h2))
			})
		})

		t.Run("Unhappy path", func(t *testing.T) {
			t.Run("Return false for different hashes of the same password", func(t *testing.T) {
				h1, err := vo.ParseHashedPassword(bcryptHash(t, "secret"))
				require.NoError(t, err)
				h2, err := vo.ParseHashedPassword(bcryptHash(t, "secret"))
				require.NoError(t, err)
				assert.False(t, h1.Equals(h2), "bcrypt uses a random salt")
			})

			t.Run("Behavior when comparing with zero value HashedPassword", func(t *testing.T) {
				var zero vo.HashedPassword
				hashed, err := vo.ParseHashedPassword(bcryptHash(t, "secret"))
				require.NoError(t, err)
				assert.False(t, zero.Equals(hashed))
				assert.False(t, hashed.Equals(zero))
				assert.True(t, zero.Equals(zero))
			})
		})
	})

	t.Run("String", func(t *testing.T) {
		t.Run("Happy path", func(t *testing.T) {
			t.Run("Mask the hash", func(t *testing.T) {
				hashed, err := vo.ParseHashedPassword(bcryptHash(t, "secret"))
				require.NoError(t, err)
				assert.Equal(t, "********", hashed.String())
			})
		})
	})

	t.Run("MarshalJSON", func(t *testing.T) {
		t.Run("Happy path", func(t *testing.T) {
			t.Run("Serialize a masked hash", func(t *testing.T) {
				hashed, err := vo.ParseHashedPassword(bcryptHash(t, "secret"))
				require.NoError(t, err)
				jsonData, err := json.Marshal(hashed)
				require.NoError(t, err)
				assert.Equal(t, `"********"`, string(jsonData))
			})
		})
	})

	t.Run("UnmarshalJSON", func(t *testing.T) {
		t.Run("Happy path", func(t *testing.T) {
			t.Run("Parse hash from JSON string", func(t *testing.T) {
				h := bcryptHash(t, "secret")
				data, err := json.Marshal(h)
				require.NoError(t, err)

				var hashed vo.HashedPassword
				require.NoError(t, json.Unmarshal(data, &hashed))
				assert.Equal(t, h, hashed.Value())
			})
		})

		t.Run("Unhappy path", func(t *testing.T) {
			t.Run("Returns error for unexpected type in JSON", func(t *testing.T) {
				var hashed vo.HashedPassword
				err := json.Unmarshal([]byte(`123`), &hashed)
				require.Error(t, err)
			})

			t.Run("Returns error for invalid hash in JSON", func(t *testing.T) {
				var hashed vo.HashedPassword
				err := json.Unmarshal([]byte(`"secret"`), &hashed)
				require.Error(t, err)
				assert.Empty(t, hashed.Value())
			})
		})
	})
}
