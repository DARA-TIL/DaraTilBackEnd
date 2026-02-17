package lessonUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type CreateUC struct {
	repo repo.LessonRepo
}

func NewCreateUC(repo repo.LessonRepo) *CreateUC {
	return &CreateUC{repo: repo}
}

func (u *CreateUC) Execute(ctx context.Context, lesson models.Lesson) (*models.Lesson, error) {
	return u.repo.Create(ctx, lesson)
}
