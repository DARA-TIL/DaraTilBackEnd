package testUC

import (
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type DeleteQuestionUC struct {
	repo repo.TestRepo
}

func NewDeleteQuestionUC(repo repo.TestRepo) *DeleteQuestionUC {
	return &DeleteQuestionUC{repo: repo}
}

func (uc *DeleteQuestionUC) Execute(ctx context.Context, id uint) error {
	return uc.repo.DeleteQuestion(ctx, id)
}
