package jwtTokenUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type FindUC struct {
	repo repo.JwtTokensRepo
}

func NewFindUC(repo repo.JwtTokensRepo) *FindUC {
	return &FindUC{repo: repo}
}
func (uc *FindUC) Execute(ctx context.Context, userId int, refreshToken string) (*models.Token, error) {
	return uc.repo.Find(ctx, userId, refreshToken)
}
