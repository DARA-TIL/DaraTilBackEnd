package lessonUC

import (
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type DeleteUC struct {
	repo repo.LessonRepo
}

func NewDeleteUC(repo repo.LessonRepo) *DeleteUC {
	return &DeleteUC{repo: repo}
}
func (u *DeleteUC) Execute(ctx context.Context, id int) error {
	return u.repo.Delete(ctx, id)
}
