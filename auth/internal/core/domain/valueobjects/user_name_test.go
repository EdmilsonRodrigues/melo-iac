package valueobjects_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	vo "github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/domain/valueobjects"
)

func TestUserName(t *testing.T) {
	t.Run("Parse", func(t *testing.T) {
		t.Run("Happy path", func(t *testing.T) {
			t.Run("Parse a valid user name", func(t *testing.T) {
				name, err := vo.ParseUserName("admin")
				require.NoError(t, err)
				assert.Equal(t, "admin", name.Value())
			})

			t.Run("Keep the original casing", func(t *testing.T) {
				name, err := vo.ParseUserName("Admin@Melo.io")
				require.NoError(t, err)
				assert.Equal(t, "Admin@Melo.io", name.Value())
			})

			t.Run("Trim surrounding whitespace", func(t *testing.T) {
				name, err := vo.ParseUserName("  admin  ")
				require.NoError(t, err)
				assert.Equal(t, "admin", name.Value())
			})

			t.Run("Accept the minimum size", func(t *testing.T) {
				name, err := vo.ParseUserName("ab")
				require.NoError(t, err)
				assert.Equal(t, "ab", name.Value())
			})

			t.Run("Accept the maximum size", func(t *testing.T) {
				s := strings.Repeat("a", 64)
				name, err := vo.ParseUserName(s)
				require.NoError(t, err)
				assert.Equal(t, s, name.Value())
			})

			t.Run("Count characters, not bytes", func(t *testing.T) {
				name, err := vo.ParseUserName("çã")
				require.NoError(t, err)
				assert.Equal(t, "çã", name.Value())
			})
		})

		t.Run("Unhappy path", func(t *testing.T) {
			t.Run("Return error when string is empty", func(t *testing.T) {
				_, err := vo.ParseUserName("")
				require.Error(t, err)
				assert.Contains(t, err.Error(), "user name too short")
			})

			t.Run("Return error when string is only whitespace", func(t *testing.T) {
				_, err := vo.ParseUserName("    ")
				require.Error(t, err)
				assert.Contains(t, err.Error(), "user name too short")
			})

			t.Run("Return error when string is too short", func(t *testing.T) {
				_, err := vo.ParseUserName("a")
				require.Error(t, err)
				assert.Contains(t, err.Error(), "user name too short")
			})

			t.Run("Return error when string is too long", func(t *testing.T) {
				_, err := vo.ParseUserName(strings.Repeat("a", 65))
				require.Error(t, err)
				assert.Contains(t, err.Error(), "user name too long")
			})
		})
	})

	t.Run("Value", func(t *testing.T) {
		t.Run("Unhappy path", func(t *testing.T) {
			t.Run("Return empty string for zero value UserName", func(t *testing.T) {
				var name vo.UserName
				assert.Empty(t, name.Value())
			})
		})
	})

	t.Run("Equals", func(t *testing.T) {
		t.Run("Happy path", func(t *testing.T) {
			t.Run("Return true for equal names", func(t *testing.T) {
				name1, err := vo.ParseUserName("admin")
				require.NoError(t, err)
				name2, err := vo.ParseUserName(" admin ")
				require.NoError(t, err)
				assert.True(t, name1.Equals(name2))
			})
		})

		t.Run("Unhappy path", func(t *testing.T) {
			t.Run("Return false for different names", func(t *testing.T) {
				name1, err := vo.ParseUserName("admin")
				require.NoError(t, err)
				name2, err := vo.ParseUserName("root")
				require.NoError(t, err)
				assert.False(t, name1.Equals(name2))
			})

			t.Run("Names are case sensitive", func(t *testing.T) {
				name1, err := vo.ParseUserName("admin")
				require.NoError(t, err)
				name2, err := vo.ParseUserName("Admin")
				require.NoError(t, err)
				assert.False(t, name1.Equals(name2))
			})

			t.Run("Behavior when comparing with zero value UserName", func(t *testing.T) {
				var zero vo.UserName
				name, err := vo.ParseUserName("admin")
				require.NoError(t, err)
				assert.False(t, zero.Equals(name))
				assert.False(t, name.Equals(zero))
				assert.True(t, zero.Equals(zero))
			})
		})
	})

	t.Run("String", func(t *testing.T) {
		t.Run("Happy path", func(t *testing.T) {
			t.Run("Return the name", func(t *testing.T) {
				name, err := vo.ParseUserName("admin")
				require.NoError(t, err)
				assert.Equal(t, "admin", name.String())
			})
		})
	})

	t.Run("MarshalJSON", func(t *testing.T) {
		t.Run("Happy path", func(t *testing.T) {
			t.Run("Serialize UserName to JSON string", func(t *testing.T) {
				name, err := vo.ParseUserName("admin")
				require.NoError(t, err)
				jsonData, err := json.Marshal(name)
				require.NoError(t, err)
				assert.Equal(t, `"admin"`, string(jsonData))
			})
		})
	})

	t.Run("UnmarshalJSON", func(t *testing.T) {
		t.Run("Happy path", func(t *testing.T) {
			t.Run("Marshal then Unmarshal returns equal UserName", func(t *testing.T) {
				original, err := vo.ParseUserName("admin")
				require.NoError(t, err)

				jsonData, err := json.Marshal(original)
				require.NoError(t, err)

				var restored vo.UserName
				require.NoError(t, json.Unmarshal(jsonData, &restored))
				assert.True(t, original.Equals(restored))
			})
		})

		t.Run("Unhappy path", func(t *testing.T) {
			t.Run("Returns error for unexpected type in JSON", func(t *testing.T) {
				var name vo.UserName
				err := json.Unmarshal([]byte(`123`), &name)
				require.Error(t, err)
			})

			t.Run("Returns error for invalid name in JSON", func(t *testing.T) {
				var name vo.UserName
				err := json.Unmarshal([]byte(`"a"`), &name)
				require.Error(t, err)
				assert.Empty(t, name.Value())
			})
		})
	})
}
