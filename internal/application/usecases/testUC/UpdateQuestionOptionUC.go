package testUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type UpdateQuestionOptionUC struct {
	repo repo.TestRepo
}

func NewUpdateQuestionOptionUC(repo repo.TestRepo) *UpdateQuestionOptionUC {
	return &UpdateQuestionOptionUC{
		repo: repo,
	}
}
func (uc *UpdateQuestionOptionUC) Execute(ctx context.Context, upd models.QuestionOptionsUpdate) (*models.QuestionOption, error) {
	return uc.repo.UpdateQuestionOption(ctx, upd)
}
