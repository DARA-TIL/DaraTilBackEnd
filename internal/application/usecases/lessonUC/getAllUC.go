package lessonUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetAllUC struct {
	repo repo.LessonRepo
}

func NewGetAllUC(repo repo.LessonRepo) *GetAllUC {
	return &GetAllUC{repo: repo}
}
func (u *GetAllUC) Execute(ctx context.Context) ([]models.Lesson, error) {
	return u.repo.GetAll(ctx)
}
