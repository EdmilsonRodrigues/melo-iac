package input

import (
	"context"

	"github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/domain/valueobjects"
)

type AuthUseCase interface {
	Login(ctx context.Context, username, password string) (token string, err error)
	Logout(ctx context.Context, token string) error
	Validate(ctx context.Context, token string) (valueobjects.UserID, error)
}
