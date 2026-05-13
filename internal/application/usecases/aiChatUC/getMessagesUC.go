package aiChatUC

import (
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetMessagesUC struct {
	repo repo.AIChatMessageRepo
}

func NewGetMessagesUC(repo repo.AIChatMessageRepo) *GetMessagesUC {
	return &GetMessagesUC{repo: repo}
}

func (uc *GetMessagesUC) Execute(ctx context.Context, userID uint, id uint) ([]models.AiChatMessage, error) {
	if userID == 0 || id == 0 {
		return nil, errs.ErrInvalidInput
	}

	return uc.repo.GetByChatID(ctx, userID, id)
}
