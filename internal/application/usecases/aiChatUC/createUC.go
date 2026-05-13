package aiChatUC

import (
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
	"strings"
)

type CreateUC struct {
	repo repo.AIChatRepo
}

func NewCreateUC(repo repo.AIChatRepo) *CreateUC {
	return &CreateUC{repo: repo}
}

func (uc *CreateUC) Execute(ctx context.Context, chat models.AIChat) (*models.AIChat, error) {
	if chat.UserID == 0 {
		return nil, errs.ErrInvalidInput
	}

	chat.Name = strings.TrimSpace(chat.Name)
	if chat.Name == "" {
		chat.Name = "New Chat"
	}

	return uc.repo.Create(ctx, chat)
}
