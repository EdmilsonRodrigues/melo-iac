package aggregates

import (
	"github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/domain/domainerrors"
	vo "github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/domain/valueobjects"
)

// NewUser creates a brand-new user with a freshly generated ID.
func NewUser(name vo.UserName, password vo.HashedPassword) (User, error) {
	return RestoreUser(vo.NewUserID(), name, password)
}

// RestoreUser rebuilds an existing user, e.g. when loading it from storage.
func RestoreUser(id vo.UserID, name vo.UserName, password vo.HashedPassword) (User, error) {
	var (
		zeroID       vo.UserID
		zeroName     vo.UserName
		zeroPassword vo.HashedPassword
	)
	if id.Equals(zeroID) || name.Equals(zeroName) || password.Equals(zeroPassword) {
		return User{}, domainerrors.ErrInvalidUser
	}
	return User{id: id, name: name, password: password}, nil
}

type User struct {
	id       vo.UserID
	name     vo.UserName
	password vo.HashedPassword
}

func (u User) ID() vo.UserID {
	return u.id
}

func (u User) Name() vo.UserName {
	return u.name
}

func (u User) Password() vo.HashedPassword {
	return u.password
}

// Equals compares users by identity, not by attributes.
func (u User) Equals(other User) bool {
	return u.id.Equals(other.id)
}
