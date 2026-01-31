package userUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetUserByIdUC struct {
	repo repo.UserRepo
}

func NewGetUserByIdUC(repo repo.UserRepo) *GetUserByEmailUC {
	return &GetUserByEmailUC{
		repo: repo,
	}
}
func (uc *GetUserByIdUC) Execute(ctx context.Context, id int) (*models.User, error) {
	return uc.repo.GetByID(ctx, id)
}
