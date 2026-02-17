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
func (u UpdateUC) Execute(ctx context.Context, id int, updFields models.UpdateLessonFields) (*models.Lesson, error) {
	upd := utils.UpdateLessonFields(updFields)
	return u.repo.Update(ctx, id, upd)
}
