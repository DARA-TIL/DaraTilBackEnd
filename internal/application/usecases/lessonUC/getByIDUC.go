package lessonUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetByIDUC struct {
	repo repo.LessonRepo
}

func NewGetByIDUC(repo repo.LessonRepo) *GetByIDUC {
	return &GetByIDUC{repo: repo}
}

func (uc *GetByIDUC) Execute(ctx context.Context, id uint) (*models.Lesson, error) {
	return uc.repo.GetByID(ctx, id)
}
