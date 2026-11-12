package k8s

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

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
	userSecretPrefix = "melo-user-"
	keyUserID        = "userID"
	keyUsername      = "username"
	keyPasswordHash  = "passwordHash"

	labelManagedBy = "app.kubernetes.io/managed-by"
	labelKind      = "melo-iac.io/kind"
	managedByValue = "melo-iac-auth"
)

type UserRepository struct {
	client    kubernetes.Interface
	namespace string
}

var _ output.UserRepository = (*UserRepository)(nil)

func NewUserRepository(client kubernetes.Interface, namespace string) *UserRepository {
	return &UserRepository{client: client, namespace: namespace}
}

func (r *UserRepository) Add(ctx context.Context, u aggregates.User) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      userSecretName(u.Name()),
			Namespace: r.namespace,
			Labels: map[string]string{
				labelManagedBy: managedByValue,
				labelKind:      "user",
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			keyUserID:       []byte(u.ID().String()),
			keyUsername:     []byte(u.Name().Value()),
			keyPasswordHash: []byte(u.Password().Value()),
		},
	}

	_, err := r.client.CoreV1().Secrets(r.namespace).Create(ctx, secret, metav1.CreateOptions{})
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			return domainerrors.ErrUserAlreadyExists
		}
		return fmt.Errorf("creating user secret: %w", err)
	}
	return nil
}

func (r *UserRepository) FindByName(ctx context.Context, name vo.UserName) (aggregates.User, error) {
	secretName := userSecretName(name)

	secret, err := r.client.CoreV1().Secrets(r.namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return aggregates.User{}, domainerrors.ErrUserNotFound
		}
		return aggregates.User{}, fmt.Errorf("getting user secret: %w", err)
	}

	storedName, err := vo.ParseUserName(string(secret.Data[keyUsername]))
	if err != nil {
		return aggregates.User{}, fmt.Errorf("user secret %s has invalid %s: %w", secretName, keyUsername, err)
	}
	if !storedName.Equals(name) {
		// Defesa contra colisao de hash ou Secret editado na mao.
		return aggregates.User{}, domainerrors.ErrUserNotFound
	}

	id, err := vo.ParseUserID(string(secret.Data[keyUserID]))
	if err != nil {
		return aggregates.User{}, fmt.Errorf("user secret %s has invalid %s: %w", secretName, keyUserID, err)
	}
	hash, err := vo.ParseHashedPassword(string(secret.Data[keyPasswordHash]))
	if err != nil {
		return aggregates.User{}, fmt.Errorf("user secret %s has invalid %s: %w", secretName, keyPasswordHash, err)
	}

	user, err := aggregates.RestoreUser(id, storedName, hash)
	if err != nil {
		return aggregates.User{}, fmt.Errorf("user secret %s is corrupted: %w", secretName, err)
	}
	return user, nil
}

func userSecretName(name vo.UserName) string {
	sum := sha256.Sum256([]byte(name.Value()))
	return userSecretPrefix + hex.EncodeToString(sum[:])
}
