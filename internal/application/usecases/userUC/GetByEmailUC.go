package userUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetUserByEmailUC struct {
	repo repo.UserRepo
}

func NewGetUserByEmailUC(repo repo.UserRepo) *GetUserByEmailUC {
	return &GetUserByEmailUC{
		repo: repo,
	}
}
func (uc *GetUserByEmailUC) Execute(ctx context.Context, email string) (*models.User, error) {
	return uc.repo.GetByEmail(ctx, email)
}
