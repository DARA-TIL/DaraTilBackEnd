package userUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetByIdUC struct {
	repo repo.UserRepo
}

func NewGetByIdUC(repo repo.UserRepo) *GetByIdUC {
	return &GetByIdUC{
		repo: repo,
	}
}
func (uc *GetByIdUC) Execute(ctx context.Context, id uint) (*models.User, error) {
	return uc.repo.GetByID(ctx, id)
}
