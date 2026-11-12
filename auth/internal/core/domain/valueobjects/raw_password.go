package valueobjects

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
)

const maxRawPasswordBytes = 72

const passwordMask = "********"

func ParseRawPassword(s string) (RawPassword, error) {
	if s == "" {
		return RawPassword{}, errors.New("password cannot be empty")
	}
	if len(s) > maxRawPasswordBytes {
		return RawPassword{}, fmt.Errorf("password too long, it is allowed at most %d bytes", maxRawPasswordBytes)
	}
	return RawPassword{s}, nil
}

type RawPassword struct {
	value string
}

func (p RawPassword) Value() string {
	return p.value
}

func (p RawPassword) Equals(other RawPassword) bool {
	return subtle.ConstantTimeCompare([]byte(p.value), []byte(other.value)) == 1
}

func (p RawPassword) String() string {
	return passwordMask
}

func (p RawPassword) MarshalJSON() ([]byte, error) {
	return json.Marshal(passwordMask)
}

func (p *RawPassword) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	parsed, err := ParseRawPassword(s)
	*p = parsed
	return err
}
