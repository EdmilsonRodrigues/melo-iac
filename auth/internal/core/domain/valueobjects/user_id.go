package valueobjects

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

func NewUserID() UserID {
	return UserID{uuid.New()}
}

func ParseUserID(s string) (UserID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return UserID{}, fmt.Errorf("invalid user id format: %w", err)
	}
	if id == uuid.Nil {
		return UserID{}, errors.New("user id cannot be a nil UUID")
	}
	return UserID{id}, nil
}

type UserID struct {
	value uuid.UUID
}

func (id UserID) Value() uuid.UUID {
	return id.value
}

func (id UserID) Equals(other UserID) bool {
	return id.value == other.value
}

func (id UserID) String() string {
	return id.value.String()
}

func (id UserID) MarshalJSON() ([]byte, error) {
	return json.Marshal(id.value.String())
}

func (id *UserID) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	parsedID, err := ParseUserID(s)
	*id = parsedID
	return err
}
