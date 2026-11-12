package aggregates

import (
	"time"

	"github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/domain/domainerrors"
	vo "github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/domain/valueobjects"
)

func NewToken(value string, userID vo.UserID, expiresAt time.Time) (Token, error) {
	var zeroID vo.UserID
	if value == "" || userID.Equals(zeroID) || expiresAt.IsZero() {
		return Token{}, domainerrors.ErrInvalidToken
	}
	return Token{value: value, userID: userID, expiresAt: expiresAt}, nil
}

// Token is an opaque session token that references its owner by UserID.
type Token struct {
	value     string
	userID    vo.UserID
	expiresAt time.Time
}

func (t Token) Value() string {
	return t.value
}

func (t Token) UserID() vo.UserID {
	return t.userID
}

func (t Token) ExpiresAt() time.Time {
	return t.expiresAt
}

// IsExpired reports whether the token is no longer valid at now.
// A token is already expired exactly at its expiration instant.
func (t Token) IsExpired(now time.Time) bool {
	return !now.Before(t.expiresAt)
}

// Equals compares tokens by identity (their value).
func (t Token) Equals(other Token) bool {
	return t.value == other.value
}
