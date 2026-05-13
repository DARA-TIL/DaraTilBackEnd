package aiChatUC

import (
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type DeleteMessageUC struct {
	repo repo.AIChatMessageRepo
}

func NewDeleteMessageUC(repo repo.AIChatMessageRepo) *DeleteMessageUC {
	return &DeleteMessageUC{repo: repo}
}

func (uc *DeleteMessageUC) Execute(ctx context.Context, userID uint, id uint) error {
	if userID == 0 || id == 0 {
		return errs.ErrInvalidInput
	}

	return uc.repo.Delete(ctx, userID, id)
}
