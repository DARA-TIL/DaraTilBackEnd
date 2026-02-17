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

func (u *DeleteBlockUC) Execute(ctx context.Context, id int) error {
	return u.repo.DeleteBlock(ctx, id)
}
