package testUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type UpdateQuestionUC struct {
	repo repo.TestRepo
}

func NewUpdateQuestionUC(repo repo.TestRepo) *UpdateQuestionUC {
	return &UpdateQuestionUC{
		repo: repo,
	}
}
func (uc *UpdateQuestionUC) Execute(ctx context.Context, upd models.QuestionUpdate) (*models.Question, error) {
	return uc.repo.UpdateQuestion(ctx, upd)
}
