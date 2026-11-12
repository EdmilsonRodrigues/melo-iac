package valueobjects_test

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	vo "github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/domain/valueobjects"
)

func TestUserID(t *testing.T) {
	t.Run("NewUserID", func(t *testing.T) {
		t.Run("Returns a valid non-nil UUID", func(t *testing.T) {
			userID := vo.NewUserID()
			assert.NotEqual(t, uuid.Nil, userID.Value())
			assert.NotEmpty(t, userID.String())
			_, err := uuid.Parse(userID.String())
			require.NoError(t, err)
			assert.Equal(t, userID.Value().String(), userID.String())
		})

		t.Run("Return a different UUID on each call", func(t *testing.T) {
			userID1 := vo.NewUserID()
			userID2 := vo.NewUserID()
			assert.NotEqual(t, userID1.Value(), userID2.Value())
			assert.NotEqual(t, userID1.String(), userID2.String())
			assert.False(t, userID1.Equals(userID2))
		})
	})

	t.Run("Parse", func(t *testing.T) {
		t.Run("Happy path", func(t *testing.T) {
			t.Run("Parse a valid UUID string", func(t *testing.T) {
				idStr := "550e8400-e29b-41d4-a716-446655440000"
				userID, err := vo.ParseUserID(idStr)
				require.NoError(t, err)
				assert.Equal(t, idStr, userID.String())
			})

			t.Run("Parse a valid UUID string with uppercase letters", func(t *testing.T) {
				idStr := "550E8400-E29B-41D4-A716-446655440000"
				userID, err := vo.ParseUserID(idStr)
				require.NoError(t, err)
				assert.Equal(t, "550e8400-e29b-41d4-a716-446655440000", userID.String())
			})
		})

		t.Run("Unhappy path", func(t *testing.T) {
			t.Run("Return error when string is empty", func(t *testing.T) {
				_, err := vo.ParseUserID("")
				require.Error(t, err)
			})

			t.Run("Return error when string is not a UUID", func(t *testing.T) {
				_, err := vo.ParseUserID("invalid-uuid-string")
				require.Error(t, err)
			})

			t.Run("Return error when string is a nil UUID", func(t *testing.T) {
				_, err := vo.ParseUserID("00000000-0000-0000-0000-000000000000")
				require.Error(t, err)
				assert.Contains(t, err.Error(), "user id cannot be a nil UUID")
			})

			t.Run("Return error when UUID has wrong length", func(t *testing.T) {
				_, err := vo.ParseUserID("123e4567-e89b-12d3-a456-42661417489")
				require.Error(t, err)
			})

			t.Run("Return error when UUID has wrong format", func(t *testing.T) {
				_, err := vo.ParseUserID("123e4567_e89b_12d3_a456_42661417489Z")
				require.Error(t, err)
				assert.Contains(t, err.Error(), "invalid user id format")
			})
		})
	})

	t.Run("Value", func(t *testing.T) {
		t.Run("Happy path", func(t *testing.T) {
			t.Run("Return the uuid.UUID", func(t *testing.T) {
				idStr := "550e8400-e29b-41d4-a716-446655440000"
				userID, err := vo.ParseUserID(idStr)
				require.NoError(t, err)
				assert.Equal(t, uuid.MustParse(idStr), userID.Value())
			})
		})

		t.Run("Unhappy path", func(t *testing.T) {
			t.Run("Return uuid.Nil for zero value UserID", func(t *testing.T) {
				var userID vo.UserID
				assert.Equal(t, uuid.Nil, userID.Value())
			})
		})
	})

	t.Run("Equals", func(t *testing.T) {
		t.Run("Happy path", func(t *testing.T) {
			t.Run("Return true for equal IDs", func(t *testing.T) {
				idStr := "550e8400-e29b-41d4-a716-446655440000"
				userID1, err := vo.ParseUserID(idStr)
				require.NoError(t, err)
				userID2, err := vo.ParseUserID(idStr)
				require.NoError(t, err)
				assert.True(t, userID1.Equals(userID2))
			})

			t.Run("Return true for same ID parsed from uppercase and lowercase", func(t *testing.T) {
				userID1, err := vo.ParseUserID("550E8400-E29B-41D4-A716-446655440000")
				require.NoError(t, err)
				userID2, err := vo.ParseUserID("550e8400-e29b-41d4-a716-446655440000")
				require.NoError(t, err)
				assert.True(t, userID1.Equals(userID2))
			})
		})

		t.Run("Unhappy path", func(t *testing.T) {
			t.Run("Return false for different IDs", func(t *testing.T) {
				userID1, err := vo.ParseUserID("550e8400-e29b-41d4-a716-446655440000")
				require.NoError(t, err)
				userID2, err := vo.ParseUserID("550e8400-e29b-41d4-a716-446655440001")
				require.NoError(t, err)
				assert.False(t, userID1.Equals(userID2))
			})

			t.Run("Behavior when comparing with zero value UserID", func(t *testing.T) {
				var zeroUserID vo.UserID
				userID, err := vo.ParseUserID("550e8400-e29b-41d4-a716-446655440000")
				require.NoError(t, err)
				assert.False(t, zeroUserID.Equals(userID))
				assert.False(t, userID.Equals(zeroUserID))
				assert.True(t, zeroUserID.Equals(zeroUserID))
			})
		})
	})

	t.Run("String", func(t *testing.T) {
		t.Run("Happy path", func(t *testing.T) {
			t.Run("Return the UUID as lowercase string", func(t *testing.T) {
				idStr := "550e8400-e29b-41d4-a716-446655440000"
				userID, err := vo.ParseUserID(idStr)
				require.NoError(t, err)
				assert.Equal(t, idStr, userID.String())
			})
		})

		t.Run("Unhappy path", func(t *testing.T) {
			t.Run("Return nil UUID string for zero value UserID", func(t *testing.T) {
				var userID vo.UserID
				assert.Equal(t, "00000000-0000-0000-0000-000000000000", userID.String())
			})
		})
	})

	t.Run("MarshalJSON", func(t *testing.T) {
		t.Run("Happy path", func(t *testing.T) {
			t.Run("Serialize UserID to JSON string", func(t *testing.T) {
				idStr := "550e8400-e29b-41d4-a716-446655440000"
				userID, err := vo.ParseUserID(idStr)
				require.NoError(t, err)
				jsonData, err := json.Marshal(&userID)
				require.NoError(t, err)
				assert.Equal(t, `"`+idStr+`"`, string(jsonData))
			})

			t.Run("Serialize UserID by value inside a struct", func(t *testing.T) {
				idStr := "550e8400-e29b-41d4-a716-446655440000"
				userID, err := vo.ParseUserID(idStr)
				require.NoError(t, err)
				jsonData, err := json.Marshal(struct{ ID vo.UserID }{ID: userID})
				require.NoError(t, err)
				assert.Equal(t, `{"ID":"`+idStr+`"}`, string(jsonData))
			})
		})
	})

	t.Run("UnmarshalJSON", func(t *testing.T) {
		t.Run("Happy path", func(t *testing.T) {
			t.Run("Marshal then Unmarshal returns equal UserID", func(t *testing.T) {
				original := vo.NewUserID()

				jsonData, err := json.Marshal(&original)
				require.NoError(t, err)

				var restored vo.UserID
				err = json.Unmarshal(jsonData, &restored)
				require.NoError(t, err)

				assert.True(t, original.Equals(restored))
				assert.Equal(t, original.String(), restored.String())
			})
		})

		t.Run("Unhappy path", func(t *testing.T) {
			t.Run("Returns error for unexpected type in JSON", func(t *testing.T) {
				var userID vo.UserID
				err := json.Unmarshal([]byte(`123`), &userID)
				require.Error(t, err)
			})

			t.Run("Returns error for invalid UUID string in JSON", func(t *testing.T) {
				var userID vo.UserID
				err := json.Unmarshal([]byte(`"invalid-uuid-string"`), &userID)
				require.Error(t, err)
				assert.Equal(t, uuid.Nil, userID.Value())
			})

			t.Run("Returns error for nil UUID in JSON", func(t *testing.T) {
				var userID vo.UserID
				err := json.Unmarshal([]byte(`"00000000-0000-0000-0000-000000000000"`), &userID)
				require.Error(t, err)
				assert.Equal(t, uuid.Nil, userID.Value())
			})
		})
	})
}
