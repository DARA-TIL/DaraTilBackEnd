package testUC

import (
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type CheckAnswerUC struct {
	repo repo.TestRepo
}

func NewCheckAnswerUC(repo repo.TestRepo) *CheckAnswerUC {
	return &CheckAnswerUC{repo: repo}
}

func (uc *CheckAnswerUC) Execute(ctx context.Context, id uint) (bool, error) {
	qo, err := uc.repo.GetOptionByID(ctx, id)
	if err != nil {
		return false, err
	}
	return qo.IsCorrect, nil
}
