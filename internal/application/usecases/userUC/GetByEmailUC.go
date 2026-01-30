package userUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetUserByEmailUC struct {
	Repo repo.UserRepo
}

func NewGetUserByEmailUC(repo repo.UserRepo) *GetUserByEmailUC {
	return &GetUserByEmailUC{
		Repo: repo,
	}
}
func (uc *GetUserByEmailUC) Execute(ctx context.Context, email string) (*models.User, error) {
	return uc.Repo.GetByEmail(ctx, email)
}
