package service_test

import (
	"context"
	"time"

	"github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/domain/aggregates"
	"github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/domain/domainerrors"
	vo "github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/domain/valueobjects"
)

type fakeUsers struct {
	users map[string]aggregates.User
	err   error
}

func newFakeUsers(us ...aggregates.User) *fakeUsers {
	f := &fakeUsers{
		users: make(map[string]aggregates.User),
	}
	for _, u := range us {
		f.users[u.Name().Value()] = u
	}
	return f
}

func (f *fakeUsers) Add(_ context.Context, u aggregates.User) error {
	if f.err != nil {
		return f.err
	}
	if _, ok := f.users[u.Name().Value()]; ok {
		return domainerrors.ErrUserAlreadyExists
	}
	f.users[u.Name().Value()] = u
	return nil
}

func (f *fakeUsers) FindByName(_ context.Context, name vo.UserName) (aggregates.User, error) {
	if f.err != nil {
		return aggregates.User{}, f.err
	}
	u, ok := f.users[name.Value()]
	if !ok {
		return aggregates.User{}, domainerrors.ErrUserNotFound
	}
	return u, nil
}

type fakeTokens struct {
	tokens    map[string]aggregates.Token
	err       error // falha do Save
	findErr   error
	revokeErr error
}

func newFakeTokens() *fakeTokens {
	return &fakeTokens{tokens: make(map[string]aggregates.Token)}
}

func (f *fakeTokens) Save(_ context.Context, t aggregates.Token) error {
	if f.err != nil {
		return f.err
	}
	f.tokens[t.Value()] = t
	return nil
}

func (f *fakeTokens) FindByValue(_ context.Context, value string) (aggregates.Token, error) {
	if f.findErr != nil {
		return aggregates.Token{}, f.findErr
	}
	t, ok := f.tokens[value]
	if !ok {
		return aggregates.Token{}, domainerrors.ErrInvalidToken
	}
	return t, nil
}

func (f *fakeTokens) Revoke(_ context.Context, value string) error {
	if f.revokeErr != nil {
		return f.revokeErr
	}
	delete(f.tokens, value)
	return nil
}

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }
