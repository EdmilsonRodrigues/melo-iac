package handler

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/domain/domainerrors"
	"github.com/EdmilsonRodrigues/melo-iac/auth/internal/core/ports/input"
)

const maxBodyBytes = 1 << 20

type AuthHandler struct {
	uc input.AuthUseCase
}

func NewAuthHandler(uc input.AuthUseCase) *AuthHandler {
	return &AuthHandler{uc: uc}
}

func (h *AuthHandler) Routes() http.Handler {
	r := gin.New()
	r.Use(gin.Recovery())
	// nil desliga a confianca em proxies; so falha com CIDR invalido, ou seja, bug nosso.
	if err := r.SetTrustedProxies(nil); err != nil {
		panic(err)
	}
	r.HandleMethodNotAllowed = true

	v1 := r.Group("/api/v1/auth")
	v1.POST("/login", h.login)
	v1.POST("/logout", h.logout)
	return r
}

type loginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type tokenResponse struct {
	Token string `json:"token"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func (h *AuthHandler) login(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBodyBytes)

	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		return
	}

	token, err := h.uc.Login(c.Request.Context(), req.Username, req.Password)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, tokenResponse{Token: token})
}

func (h *AuthHandler) logout(c *gin.Context) {
	token, ok := bearerToken(c.GetHeader("Authorization"))
	if !ok {
		c.JSON(http.StatusUnauthorized, errorResponse{Error: "missing bearer token"})
		return
	}

	if err := h.uc.Logout(c.Request.Context(), token); err != nil {
		h.fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *AuthHandler) fail(c *gin.Context, err error) {
	switch {
	case errors.Is(err, domainerrors.ErrInvalidCredentials):
		c.JSON(http.StatusUnauthorized, errorResponse{Error: "invalid credentials"})
	default:
		slog.Error("request failed", "path", c.FullPath(), "error", err)
		c.JSON(http.StatusInternalServerError, errorResponse{Error: "internal error"})
	}
}

func bearerToken(header string) (string, bool) {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return "", false
	}
	token := strings.TrimSpace(header[len(prefix):])
	return token, token != ""
}
