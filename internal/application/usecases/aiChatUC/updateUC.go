package aiChatUC

import (
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
	"strings"
)

type UpdateUC struct {
	repo repo.AIChatRepo
}

func NewUpdateUC(repo repo.AIChatRepo) *UpdateUC {
	return &UpdateUC{repo: repo}
}

func (uc *UpdateUC) Execute(ctx context.Context, userID uint, id uint, name string) (*models.AIChat, error) {
	if userID == 0 || id == 0 {
		return nil, errs.ErrInvalidInput
	}

	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errs.ErrInvalidInput
	}

	return uc.repo.Update(ctx, userID, id, name)
}
