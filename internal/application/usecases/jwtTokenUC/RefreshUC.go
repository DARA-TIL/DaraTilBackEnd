package jwtTokenUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type FindTokenUC struct {
	repo repo.JwtTokensRepo
}

func NewFindTokenUC(repo repo.JwtTokensRepo) *FindTokenUC {
	return &FindTokenUC{repo: repo}
}
func (uc *FindTokenUC) Execute(ctx context.Context, userId int, refreshToken string) (*models.Token, error) {
	return uc.repo.Find(ctx, userId, refreshToken)
}
