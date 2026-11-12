package valueobjects

import (
	"encoding/json"
	"errors"

	"golang.org/x/crypto/bcrypt"
)

const bcryptHashSize = 60

var errInvalidHashedPassword = errors.New("invalid hashed password: expected a bcrypt hash")

func ParseHashedPassword(s string) (HashedPassword, error) {
	if len(s) != bcryptHashSize {
		return HashedPassword{}, errInvalidHashedPassword
	}
	if _, err := bcrypt.Cost([]byte(s)); err != nil {
		return HashedPassword{}, errInvalidHashedPassword
	}
	return HashedPassword{s}, nil
}

type HashedPassword struct {
	value string
}

func (h HashedPassword) Value() string {
	return h.value
}

func (h HashedPassword) Equals(other HashedPassword) bool {
	return h.value == other.value
}

func (h HashedPassword) String() string {
	return passwordMask
}

func (h HashedPassword) MarshalJSON() ([]byte, error) {
	return json.Marshal(passwordMask)
}

func (h *HashedPassword) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	parsed, err := ParseHashedPassword(s)
	*h = parsed
	return err
}
