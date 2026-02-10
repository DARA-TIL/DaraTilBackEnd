package userUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetByUsernameUC struct {
	repo repo.UserRepo
}

func NewGetByUsernameUC(repo repo.UserRepo) *GetByUsernameUC {
	return &GetByUsernameUC{repo: repo}
}

func (uc *GetByUsernameUC) Execute(ctx context.Context, username string) ([]models.User, error) {
	return uc.repo.GetByUsername(ctx, username)
}
