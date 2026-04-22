package lessonUC

import (
	"DaraTilBackendV2/internal/application/utils"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type UpdateUC struct {
	repo repo.LessonRepo
}

func NewUpdateUC(repo repo.LessonRepo) *UpdateUC {
	return &UpdateUC{repo: repo}
}
func (uc *UpdateUC) Execute(ctx context.Context, id uint, updFields models.UpdateLessonFields) (*models.Lesson, error) {
	upd := utils.UpdateLessonFields(updFields)
	return uc.repo.Update(ctx, id, upd)
}
