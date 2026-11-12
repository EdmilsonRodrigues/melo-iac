package valueobjects_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	vo "github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/domain/valueobjects"
)

func TestRawPassword(t *testing.T) {
	t.Run("Parse", func(t *testing.T) {
		t.Run("Happy path", func(t *testing.T) {
			t.Run("Parse a valid password", func(t *testing.T) {
				password, err := vo.ParseRawPassword("secret")
				require.NoError(t, err)
				assert.Equal(t, "secret", password.Value())
			})

			t.Run("Keep surrounding whitespace", func(t *testing.T) {
				password, err := vo.ParseRawPassword("  secret  ")
				require.NoError(t, err)
				assert.Equal(t, "  secret  ", password.Value())
			})

			t.Run("Accept the maximum size of 72 bytes", func(t *testing.T) {
				s := strings.Repeat("a", 72)
				password, err := vo.ParseRawPassword(s)
				require.NoError(t, err)
				assert.Equal(t, s, password.Value())
			})
		})

		t.Run("Unhappy path", func(t *testing.T) {
			t.Run("Return error when string is empty", func(t *testing.T) {
				_, err := vo.ParseRawPassword("")
				require.Error(t, err)
				assert.Contains(t, err.Error(), "password cannot be empty")
			})

			t.Run("Return error when password exceeds 72 bytes", func(t *testing.T) {
				_, err := vo.ParseRawPassword(strings.Repeat("a", 73))
				require.Error(t, err)
				assert.Contains(t, err.Error(), "password too long")
			})

			t.Run("Count bytes, not characters", func(t *testing.T) {
				_, err := vo.ParseRawPassword(strings.Repeat("ç", 37)) // 74 bytes
				require.Error(t, err)
				assert.Contains(t, err.Error(), "password too long")
			})

			t.Run("Error message never contains the password", func(t *testing.T) {
				s := strings.Repeat("x", 73)
				_, err := vo.ParseRawPassword(s)
				require.Error(t, err)
				assert.NotContains(t, err.Error(), s)
			})
		})
	})

	t.Run("Value", func(t *testing.T) {
		t.Run("Unhappy path", func(t *testing.T) {
			t.Run("Return empty string for zero value RawPassword", func(t *testing.T) {
				var password vo.RawPassword
				assert.Empty(t, password.Value())
			})
		})
	})

	t.Run("Equals", func(t *testing.T) {
		t.Run("Happy path", func(t *testing.T) {
			t.Run("Return true for equal passwords", func(t *testing.T) {
				p1, err := vo.ParseRawPassword("secret")
				require.NoError(t, err)
				p2, err := vo.ParseRawPassword("secret")
				require.NoError(t, err)
				assert.True(t, p1.Equals(p2))
			})
		})

		t.Run("Unhappy path", func(t *testing.T) {
			t.Run("Return false for different passwords", func(t *testing.T) {
				p1, err := vo.ParseRawPassword("secret")
				require.NoError(t, err)
				p2, err := vo.ParseRawPassword("Secret")
				require.NoError(t, err)
				assert.False(t, p1.Equals(p2))
			})

			t.Run("Behavior when comparing with zero value RawPassword", func(t *testing.T) {
				var zero vo.RawPassword
				password, err := vo.ParseRawPassword("secret")
				require.NoError(t, err)
				assert.False(t, zero.Equals(password))
				assert.False(t, password.Equals(zero))
				assert.True(t, zero.Equals(zero))
			})
		})
	})

	t.Run("String", func(t *testing.T) {
		t.Run("Happy path", func(t *testing.T) {
			t.Run("Mask the password", func(t *testing.T) {
				password, err := vo.ParseRawPassword("secret")
				require.NoError(t, err)
				assert.Equal(t, "********", password.String())
			})

			t.Run("Mask the password when formatted", func(t *testing.T) {
				password, err := vo.ParseRawPassword("secret")
				require.NoError(t, err)
				assert.NotContains(t, fmt.Sprintf("%v %s %+v", password, password, password), "secret")
			})
		})
	})

	t.Run("MarshalJSON", func(t *testing.T) {
		t.Run("Happy path", func(t *testing.T) {
			t.Run("Serialize a masked password", func(t *testing.T) {
				password, err := vo.ParseRawPassword("secret")
				require.NoError(t, err)
				jsonData, err := json.Marshal(password)
				require.NoError(t, err)
				assert.Equal(t, `"********"`, string(jsonData))
			})
		})
	})

	t.Run("UnmarshalJSON", func(t *testing.T) {
		t.Run("Happy path", func(t *testing.T) {
			t.Run("Parse password from JSON string", func(t *testing.T) {
				var password vo.RawPassword
				require.NoError(t, json.Unmarshal([]byte(`"secret"`), &password))
				assert.Equal(t, "secret", password.Value())
			})
		})

		t.Run("Unhappy path", func(t *testing.T) {
			t.Run("Returns error for unexpected type in JSON", func(t *testing.T) {
				var password vo.RawPassword
				err := json.Unmarshal([]byte(`123`), &password)
				require.Error(t, err)
			})

			t.Run("Returns error for empty password in JSON", func(t *testing.T) {
				var password vo.RawPassword
				err := json.Unmarshal([]byte(`""`), &password)
				require.Error(t, err)
				assert.Empty(t, password.Value())
			})
		})
	})
}
