package userProfileUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type CreateUC struct {
	repo repo.UserProfileRepo
}

func NewCreateUC(repo repo.UserProfileRepo) *CreateUC {
	return &CreateUC{repo: repo}
}

func (uc *CreateUC) Execute(ctx context.Context, profile models.CreateUserProfile) error {
	return uc.repo.Create(ctx, profile)
}
