package jwtTokenUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type CreateUC struct {
	repo repo.JwtTokensRepo
}

func NewCreateUC(repo repo.JwtTokensRepo) *CreateUC {
	return &CreateUC{repo: repo}
}

func (uc *CreateUC) Execute(ctx context.Context, token models.Token) (*models.Token, error) {
	return uc.repo.Create(ctx, token)
}
