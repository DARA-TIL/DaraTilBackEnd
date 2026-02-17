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

func (u *GetByIDUC) Execute(ctx context.Context, id int) (*models.Lesson, error) {
	return u.repo.GetByID(ctx, id)
}
