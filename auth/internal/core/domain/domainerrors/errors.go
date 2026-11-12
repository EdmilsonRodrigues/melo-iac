package domainerrors

import "errors"

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrUserAlreadyExists  = errors.New("user already exists")
	ErrInvalidToken       = errors.New("invalid token")
	ErrInvalidUser        = errors.New("invalid user")
	ErrInvalidCredentials = errors.New("invalid credentials")
)
