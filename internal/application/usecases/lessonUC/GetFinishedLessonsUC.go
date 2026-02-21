package lessonUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetFinishedLessonsUC struct {
	repo repo.LessonRepo
}

func NewGetFinishedLessonsUC(repo repo.LessonRepo) *GetFinishedLessonsUC {
	return &GetFinishedLessonsUC{repo: repo}
}
func (uc *GetFinishedLessonsUC) Execute(ctx context.Context, userID uint) ([]models.LessonResult, error) {
	return uc.repo.GetFinishedLessons(ctx, userID)
}
