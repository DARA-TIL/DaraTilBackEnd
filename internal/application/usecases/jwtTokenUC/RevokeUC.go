package jwtTokenUC

import (
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type RevokeJwtUC struct {
	repo repo.JwtTokensRepo
}

func NewRevokeJwtUC(repo repo.JwtTokensRepo) *RevokeJwtUC {
	return &RevokeJwtUC{repo: repo}
}
func (uc *RevokeJwtUC) Execute(ctx context.Context, userID int, refreshToken string) error {
	return uc.repo.Revoke(ctx, userID, refreshToken)
}
