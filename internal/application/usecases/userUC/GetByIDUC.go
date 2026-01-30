package userUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetUserByIdUC struct {
	Repo repo.UserRepo
}

func NewGetUserByIdUC(repo repo.UserRepo) *GetUserByEmailUC {
	return &GetUserByEmailUC{
		Repo: repo,
	}
}
func (uc *GetUserByIdUC) Execute(ctx context.Context, id int) (*models.User, error) {
	return uc.Repo.GetByID(ctx, id)
}
