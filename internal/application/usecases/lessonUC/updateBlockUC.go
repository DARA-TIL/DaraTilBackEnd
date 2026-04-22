package lessonUC

import (
	"DaraTilBackendV2/internal/application/utils"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type UpdateBlockUC struct {
	repo repo.LessonRepo
}

func NewUpdateBlockUC(repo repo.LessonRepo) *UpdateBlockUC {
	return &UpdateBlockUC{repo: repo}
}
func (uc *UpdateBlockUC) Execute(ctx context.Context, id uint, updFields models.UpdateLessonBLockFields) (*models.LessonBlock, error) {
	upd := utils.UpdateLessonBlockFields(updFields)
	return uc.repo.UpdateBlock(ctx, id, upd, updFields.Position, updFields.LessonID)
}
