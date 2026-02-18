package testUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type CreateQuestionUC struct {
	repo repo.TestRepo
}

func NewCreateQuestionUC(repo repo.TestRepo) *CreateQuestionUC {
	return &CreateQuestionUC{repo: repo}
}

func (h *CreateQuestionUC) Execute(ctx context.Context, option models.Question) (*models.Question, error) {
	return h.repo.CreateQuestion(ctx, option)
}
