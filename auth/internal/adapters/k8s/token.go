package k8s

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/domain/aggregates"
	"github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/domain/domainerrors"
	vo "github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/domain/valueobjects"
	"github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/ports/output"
)

const (
	tokenSecretPrefix = "melo-token-"
	keyExpiresAt      = "expiresAt"
)

type TokenRepository struct {
	client    kubernetes.Interface
	namespace string
}

var _ output.TokenRepository = (*TokenRepository)(nil)

func NewTokenRepository(client kubernetes.Interface, namespace string) *TokenRepository {
	return &TokenRepository{client: client, namespace: namespace}
}

func (r *TokenRepository) Save(ctx context.Context, t aggregates.Token) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tokenSecretName(t.Value()),
			Namespace: r.namespace,
			Labels: map[string]string{
				labelManagedBy: managedByValue,
				labelKind:      "token",
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			keyUserID:    []byte(t.UserID().String()),
			keyExpiresAt: []byte(t.ExpiresAt().UTC().Format(time.RFC3339Nano)),
		},
	}

	if _, err := r.client.CoreV1().Secrets(r.namespace).Create(ctx, secret, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("creating token secret: %w", err)
	}
	return nil
}

func (r *TokenRepository) FindByValue(ctx context.Context, value string) (aggregates.Token, error) {
	if value == "" {
		return aggregates.Token{}, domainerrors.ErrInvalidToken
	}
	name := tokenSecretName(value)

	secret, err := r.client.CoreV1().Secrets(r.namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return aggregates.Token{}, domainerrors.ErrInvalidToken
		}
		return aggregates.Token{}, fmt.Errorf("getting token secret: %w", err)
	}

	userID, err := vo.ParseUserID(string(secret.Data[keyUserID]))
	if err != nil {
		return aggregates.Token{}, fmt.Errorf("token secret %s has invalid %s: %w", name, keyUserID, err)
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, string(secret.Data[keyExpiresAt]))
	if err != nil {
		return aggregates.Token{}, fmt.Errorf("token secret %s has invalid %s: %w", name, keyExpiresAt, err)
	}

	// %v (nao %w): se NewToken devolver ErrInvalidToken aqui, o dado no cluster
	// esta corrompido, e isso nao pode virar um 401 silencioso para o chamador.
	tok, err := aggregates.NewToken(value, userID, expiresAt)
	if err != nil {
		return aggregates.Token{}, fmt.Errorf("token secret %s is corrupted: %v", name, err) //nolint:errorlint // ver comentario acima
	}
	return tok, nil
}

func (r *TokenRepository) Revoke(ctx context.Context, value string) error {
	err := r.client.CoreV1().Secrets(r.namespace).Delete(ctx, tokenSecretName(value), metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("deleting token secret: %w", err)
	}
	return nil
}

func tokenSecretName(value string) string {
	sum := sha256.Sum256([]byte(value))
	return tokenSecretPrefix + hex.EncodeToString(sum[:])
}
