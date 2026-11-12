package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/domain/aggregates"
	"github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/domain/domainerrors"
	vo "github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/domain/valueobjects"
	"github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/ports/input"
	"github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/ports/output"
	"golang.org/x/crypto/bcrypt"
)

type BcryptHasher struct{}

func (BcryptHasher) Compare(hash vo.HashedPassword, password vo.RawPassword) error {
	return bcrypt.CompareHashAndPassword([]byte(hash.Value()), []byte(password.Value()))
}

// dummyHash is compared against when the user does not exist, so that an
// unknown user takes as long as a wrong password (no user enumeration).
var dummyHash = func() vo.HashedPassword {
	h, err := bcrypt.GenerateFromPassword([]byte("dummy-password"), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	hashed, err := vo.ParseHashedPassword(string(h))
	if err != nil {
		panic(err)
	}
	return hashed
}()

type AuthService struct {
	users  output.UserRepository
	tokens output.TokenRepository
	clock  output.Clock
	hasher output.PasswordHasher
	ttl    time.Duration
}

var _ input.AuthUseCase = (*AuthService)(nil)

func NewAuthService(
	users output.UserRepository,
	tokens output.TokenRepository,
	clock output.Clock,
	hasher output.PasswordHasher,
	ttl time.Duration,
) *AuthService {
	return &AuthService{users: users, tokens: tokens, clock: clock, hasher: hasher, ttl: ttl}
}

func (s *AuthService) Login(ctx context.Context, username, password string) (string, error) {
	name, err := vo.ParseUserName(username)
	if err != nil {
		return "", domainerrors.ErrInvalidCredentials
	}
	raw, err := vo.ParseRawPassword(password)
	if err != nil {
		return "", domainerrors.ErrInvalidCredentials
	}

	user, err := s.users.FindByName(ctx, name)
	if err != nil {
		if errors.Is(err, domainerrors.ErrUserNotFound) {
			// Result is irrelevant: this call only equalizes response time.
			_ = s.hasher.Compare(dummyHash, raw) //nolint:errcheck // timing only, see dummyHash
			return "", domainerrors.ErrInvalidCredentials
		}
		return "", fmt.Errorf("finding user: %w", err)
	}

	if s.hasher.Compare(user.Password(), raw) != nil {
		return "", domainerrors.ErrInvalidCredentials
	}

	value, err := generateTokenValue()
	if err != nil {
		return "", fmt.Errorf("generating token: %w", err)
	}

	token, err := aggregates.NewToken(value, user.ID(), s.clock.Now().Add(s.ttl))
	if err != nil {
		return "", fmt.Errorf("building token: %w", err)
	}

	if err := s.tokens.Save(ctx, token); err != nil {
		return "", fmt.Errorf("saving token: %w", err)
	}
	return token.Value(), nil
}

func (s *AuthService) Logout(ctx context.Context, token string) error {
	if err := s.tokens.Revoke(ctx, token); err != nil {
		return fmt.Errorf("revoking token: %w", err)
	}
	return nil
}

func (s *AuthService) Validate(ctx context.Context, token string) (vo.UserID, error) {
	if token == "" {
		return vo.UserID{}, domainerrors.ErrInvalidToken
	}

	t, err := s.tokens.FindByValue(ctx, token)
	if err != nil {
		if errors.Is(err, domainerrors.ErrInvalidToken) {
			return vo.UserID{}, domainerrors.ErrInvalidToken
		}
		return vo.UserID{}, fmt.Errorf("finding token: %w", err)
	}

	if t.IsExpired(s.clock.Now()) {
		return vo.UserID{}, domainerrors.ErrInvalidToken
	}
	return t.UserID(), nil
}

func generateTokenValue() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
