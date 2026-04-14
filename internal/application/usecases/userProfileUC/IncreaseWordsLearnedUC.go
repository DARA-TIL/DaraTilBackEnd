package userProfileUC

import (
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type IncreaseWordsLearnedUC struct {
	repo repo.UserProfileRepo
}

func NewIncreaseWordsLearnedUC(repo repo.UserProfileRepo) *IncreaseWordsLearnedUC {
	return &IncreaseWordsLearnedUC{repo: repo}
}

func (uc *IncreaseWordsLearnedUC) Execute(ctx context.Context, userID uint) error {
	return uc.repo.IncreaseWordsLearned(ctx, userID)
}
