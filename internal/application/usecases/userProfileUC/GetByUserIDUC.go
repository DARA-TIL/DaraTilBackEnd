package userProfileUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetByUserIDUC struct {
	repo repo.UserProfileRepo
}

func NewGetByUserIDUC(repo repo.UserProfileRepo) *GetByUserIDUC {
	return &GetByUserIDUC{repo: repo}
}

func (uc *GetByUserIDUC) Execute(ctx context.Context, userID uint) (*models.UserProfile, error) {
	return uc.repo.GetByUserID(ctx, userID)
}
