package lessonUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetBestResultForLessonUC struct {
	repo repo.LessonRepo
}

func NewGetBestResultForLessonUC(repo repo.LessonRepo) *GetBestResultForLessonUC {
	return &GetBestResultForLessonUC{repo: repo}
}
func (uc *GetBestResultForLessonUC) Execute(ctx context.Context, userID uint, lessonID uint) (*models.LessonResult, error) {
	return uc.repo.GetBestResultForLesson(ctx, userID, lessonID)
}
