package utils

import (
	"DaraTilBackendV2/internal/application/models"
	"DaraTilBackendV2/internal/config"
	errs "DaraTilBackendV2/internal/domain/domErr"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func GenerateTokenPair(user models.UserClaims, cfg *config.Config) (*models.TokenPair, error) {
	now := time.Now()
	accessExp := now.Add(time.Minute * time.Duration(cfg.Jwt.JwtAccessExpiresMin))
	refreshExp := now.Add(time.Hour * time.Duration(cfg.Jwt.JwtRefreshExpiresHours))

	accessClaims := models.CustomClaims{
		UserID:   user.UserID,
		Username: user.Username,
		Email:    user.Email,
		Role:     user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "access",
			ExpiresAt: jwt.NewNumericDate(accessExp),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	refreshClaims := models.CustomClaims{
		UserID:   user.UserID,
		Username: user.Username,
		Email:    user.Email,
		Role:     user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "refresh",
			ExpiresAt: jwt.NewNumericDate(refreshExp),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)

	access, err := accessToken.SignedString([]byte(cfg.Jwt.JwtAccessSecret))
	if err != nil {
		return nil, errs.ErrInternal
	}

	refresh, err := refreshToken.SignedString([]byte(cfg.Jwt.JwtRefreshSecret))
	if err != nil {
		return nil, errs.ErrInternal
	}
	return &models.TokenPair{
		AccessToken:  access,
		RefreshToken: refresh,
	}, nil
}
