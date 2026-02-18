package testUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetByLessonIDUC struct {
	repo repo.TestRepo
}

func NewGetByLessonIDUC(repo repo.TestRepo) *GetByLessonIDUC {
	return &GetByLessonIDUC{repo: repo}
}

func (uc *GetByLessonIDUC) Execute(ctx context.Context, id uint) (*models.Test, error) {
	return uc.repo.GetById(ctx, id)
}
