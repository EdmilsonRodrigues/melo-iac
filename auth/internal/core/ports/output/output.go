package output

import (
	"context"
	"time"

	"github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/domain/aggregates"
	"github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/domain/valueobjects"
)

type UserRepository interface {
	Add(ctx context.Context, u aggregates.User) error
	FindByName(ctx context.Context, name valueobjects.UserName) (aggregates.User, error)
}

type TokenRepository interface {
	Save(ctx context.Context, t aggregates.Token) error
	FindByValue(ctx context.Context, value string) (aggregates.Token, error)
	Revoke(ctx context.Context, value string) error
}

type PasswordHasher interface {
	Compare(hash valueobjects.HashedPassword, password valueobjects.RawPassword) error
}

type Clock interface {
	Now() time.Time
}
