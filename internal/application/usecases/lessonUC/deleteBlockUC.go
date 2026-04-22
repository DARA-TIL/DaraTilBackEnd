package lessonUC

import (
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type DeleteBlockUC struct {
	repo repo.LessonRepo
}

func NewDeleteBlockUC(repo repo.LessonRepo) *DeleteBlockUC {
	return &DeleteBlockUC{
		repo: repo,
	}
}

func (uc *DeleteBlockUC) Execute(ctx context.Context, id uint) error {
	return uc.repo.DeleteBlock(ctx, id)
}
