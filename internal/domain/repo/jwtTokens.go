package repo

import (
	"DaraTilBackendV2/internal/domain/models"
	"context"
)

type JwtTokensRepo interface {
	Create(ctx context.Context, token models.Token) (*models.Token, error)
	Find(ctx context.Context, userId uint, refreshToken string) (*models.Token, error)
	Revoke(ctx context.Context, userId uint, refreshToken string) error
}
