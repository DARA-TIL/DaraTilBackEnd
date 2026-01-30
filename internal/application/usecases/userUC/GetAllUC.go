package userUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetAllUsersUC struct {
	repo repo.UserRepo
}

func NewGetAllUsersUC(repo repo.UserRepo) *GetAllUsersUC {
	return &GetAllUsersUC{repo: repo}
}

func (uc *GetAllUsersUC) Execute(ctx context.Context) ([]models.User, error) {
	return uc.repo.GetAll(ctx)
}
