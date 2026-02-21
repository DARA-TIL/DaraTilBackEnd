package lessonUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetLessonResultsUC struct {
	repo repo.LessonRepo
}

func NewGetLessonResultsUC(repo repo.LessonRepo) *GetLessonResultsUC {
	return &GetLessonResultsUC{repo: repo}
}
func (uc *GetLessonResultsUC) Execute(ctx context.Context, userID, lessonID uint) ([]models.LessonResult, error) {
	return uc.repo.GetLessonResults(ctx, userID, lessonID)
}
