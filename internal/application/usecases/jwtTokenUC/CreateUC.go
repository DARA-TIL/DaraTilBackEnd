package jwtTokenUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type CreateTokenUC struct {
	repo repo.JwtTokensRepo
}

func NewCreateTokenUC(repo repo.JwtTokensRepo) *CreateTokenUC {
	return &CreateTokenUC{repo: repo}
}

func (uc *CreateTokenUC) Execute(ctx context.Context, token models.Token) (*models.Token, error) {
	return uc.repo.Create(ctx, token)
}
