package lessonUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type FinishLessonUC struct {
	repo repo.LessonRepo
}

func NewFinishLessonUC(repo repo.LessonRepo) *FinishLessonUC {
	return &FinishLessonUC{repo: repo}
}

func (uc *FinishLessonUC) Execute(ctx context.Context, lesRes models.LessonResult) (*models.LessonResult, error) {
	return uc.repo.FinishLesson(ctx, lesRes)
}
