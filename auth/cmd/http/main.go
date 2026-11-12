package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/EdmilsonRodrigues/melo-iac/auth/internal/adapters/handler"
	"github.com/EdmilsonRodrigues/melo-iac/auth/internal/adapters/k8s"
	"github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/domain/aggregates"
	"github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/domain/domainerrors"
	vo "github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/domain/valueobjects"
	"github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/ports/output"
	"github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/service"
)

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

func main() {
	if err := run(); err != nil {
		slog.Error("auth service stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	port := getenv("AUTH_PORT", "8081")
	namespace := getenv("AUTH_NAMESPACE", "melo-system")
	ttl, err := time.ParseDuration(getenv("AUTH_TOKEN_TTL", "24h"))
	if err != nil {
		return fmt.Errorf("invalid AUTH_TOKEN_TTL: %w", err)
	}

	client, err := newKubeClient()
	if err != nil {
		return err
	}
	users := k8s.NewUserRepository(client, namespace)
	tokens := k8s.NewTokenRepository(client, namespace)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := bootstrapAdmin(ctx, users); err != nil {
		return err
	}

	svc := service.NewAuthService(users, tokens, systemClock{}, service.BcryptHasher{}, ttl)
	h := handler.NewAuthHandler(svc)

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           h.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("auth listening", "port", port, "namespace", namespace)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		slog.Info("shutting down")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

func newKubeClient() (kubernetes.Interface, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		cfg, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			clientcmd.NewDefaultClientConfigLoadingRules(),
			&clientcmd.ConfigOverrides{},
		).ClientConfig()
		if err != nil {
			return nil, fmt.Errorf("loading kube config: %w", err)
		}
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating kube client: %w", err)
	}
	return client, nil
}

func bootstrapAdmin(ctx context.Context, users output.UserRepository) error {
	username := os.Getenv("MELO_ADMIN_USER")
	password := os.Getenv("MELO_ADMIN_PASSWORD")
	if username == "" && password == "" {
		return nil
	}
	if username == "" || password == "" {
		return errors.New("MELO_ADMIN_USER and MELO_ADMIN_PASSWORD must be set together")
	}

	name, err := vo.ParseUserName(username)
	if err != nil {
		return fmt.Errorf("invalid MELO_ADMIN_USER: %w", err)
	}
	// Valida as regras de senha antes de gastar CPU com o bcrypt.
	raw, err := vo.ParseRawPassword(password)
	if err != nil {
		return fmt.Errorf("invalid MELO_ADMIN_PASSWORD: %w", err)
	}

	h, err := bcrypt.GenerateFromPassword([]byte(raw.Value()), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hashing admin password: %w", err)
	}
	hash, err := vo.ParseHashedPassword(string(h))
	if err != nil {
		return fmt.Errorf("hashing admin password: %w", err)
	}

	user, err := aggregates.NewUser(name, hash)
	if err != nil {
		return fmt.Errorf("invalid admin user: %w", err)
	}

	err = users.Add(ctx, user)
	if errors.Is(err, domainerrors.ErrUserAlreadyExists) {
		slog.Info("admin user already exists", "username", user.Name().Value())
		return nil
	}
	if err != nil {
		return fmt.Errorf("creating admin user: %w", err)
	}
	slog.Info("admin user created", "username", user.Name().Value())
	return nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
