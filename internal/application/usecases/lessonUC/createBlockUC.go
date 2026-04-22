package lessonUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type CreateBlockUC struct {
	repo repo.LessonRepo
}

func NewCreateBlockUC(repo repo.LessonRepo) *CreateBlockUC {
	return &CreateBlockUC{repo: repo}
}

func (uc *CreateBlockUC) Execute(ctx context.Context, block models.LessonBlock) (*models.LessonBlock, error) {
	return uc.repo.CreateBlock(ctx, block)
}
