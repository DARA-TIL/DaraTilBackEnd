package userUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetAllUC struct {
	repo repo.UserRepo
}

func NewGetAllUC(repo repo.UserRepo) *GetAllUC {
	return &GetAllUC{repo: repo}
}

func (uc *GetAllUC) Execute(ctx context.Context) ([]models.User, error) {
	return uc.repo.GetAll(ctx)
}
