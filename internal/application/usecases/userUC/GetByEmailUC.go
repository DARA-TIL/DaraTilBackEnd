package userUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetByEmailUC struct {
	repo repo.UserRepo
}

func NewGetByEmailUC(repo repo.UserRepo) *GetByEmailUC {
	return &GetByEmailUC{
		repo: repo,
	}
}
func (uc *GetByEmailUC) Execute(ctx context.Context, email string) (*models.User, error) {
	return uc.repo.GetByEmail(ctx, email)
}
