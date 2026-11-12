package valueobjects

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	minUserNameSize = 2
	maxUserNameSize = 64
)

func ParseUserName(s string) (UserName, error) {
	s = strings.TrimSpace(s)
	size := utf8.RuneCountInString(s)
	if size < minUserNameSize {
		return UserName{}, fmt.Errorf("user name too short, it is required at least %d characters", minUserNameSize)
	}
	if size > maxUserNameSize {
		return UserName{}, fmt.Errorf("user name too long, it is allowed at most %d characters", maxUserNameSize)
	}
	return UserName{s}, nil
}

type UserName struct {
	value string
}

func (name UserName) Value() string {
	return name.value
}

func (name UserName) Equals(other UserName) bool {
	return name.value == other.value
}

func (name UserName) String() string {
	return name.value
}

func (name UserName) MarshalJSON() ([]byte, error) {
	return json.Marshal(name.value)
}

func (name *UserName) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	parsedName, err := ParseUserName(s)
	*name = parsedName
	return err
}
