package testUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type CreateOptionUC struct {
	repo repo.TestRepo
}

func NewCreateOptionUC(repo repo.TestRepo) *CreateOptionUC {
	return &CreateOptionUC{repo: repo}
}

func (uc *CreateOptionUC) Execute(ctx context.Context, option models.QuestionOption) (*models.QuestionOption, error) {
	return uc.repo.CreateOption(ctx, option)
}
