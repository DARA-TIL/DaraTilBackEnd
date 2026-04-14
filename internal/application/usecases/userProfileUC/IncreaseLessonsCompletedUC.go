package userProfileUC

import (
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type IncreaseLessonsCompletedUC struct {
	repo repo.UserProfileRepo
}

func NewIncreaseLessonsCompletedUC(repo repo.UserProfileRepo) *IncreaseLessonsCompletedUC {
	return &IncreaseLessonsCompletedUC{repo: repo}
}

func (uc *IncreaseLessonsCompletedUC) Execute(ctx context.Context, userID uint) error {
	return uc.repo.IncreaseLessonsCompleted(ctx, userID)
}
