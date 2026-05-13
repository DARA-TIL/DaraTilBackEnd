package aiChatUC

import (
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type DeleteUC struct {
	repo repo.AIChatRepo
}

func NewDeleteUC(repo repo.AIChatRepo) *DeleteUC {
	return &DeleteUC{repo: repo}
}

func (uc *DeleteUC) Execute(ctx context.Context, userID uint, id uint) error {
	if userID == 0 || id == 0 {
		return errs.ErrInvalidInput
	}

	return uc.repo.Delete(ctx, userID, id)
}
