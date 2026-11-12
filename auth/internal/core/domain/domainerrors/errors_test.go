package domainerrors_test

import (
	"fmt"
	"testing"

	err "github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/domain/domainerrors"
	"github.com/stretchr/testify/assert"
)

func TestDomainErrors(t *testing.T) {
	all := []struct {
		name string
		err  error
	}{
		{name: "ErrUserNotFound", err: err.ErrUserNotFound},
		{name: "ErrUserAlreadyExists", err: err.ErrUserAlreadyExists},
		{name: "ErrInvalidUser", err: err.ErrInvalidUser},
		{name: "ErrInvalidToken", err: err.ErrInvalidToken},
		{name: "ErrInvalidCredentials", err: err.ErrInvalidCredentials},
	}

	for _, tt := range all {
		t.Run(tt.name, func(t *testing.T) {
			wrapped := fmt.Errorf("adapter: %w", tt.err)

			assert.ErrorIs(t, wrapped, tt.err, "errors.Is must see through %%w wrapping")

			for _, other := range all {
				if other.name == tt.name {
					continue
				}
				assert.NotErrorIs(t, wrapped, other.err, "%s must not match %s", tt.name, other.name)
			}
		})
	}
}
