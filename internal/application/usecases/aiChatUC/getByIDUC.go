package aiChatUC

import (
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetByIDUC struct {
	repo repo.AIChatRepo
}

func NewGetByIDUC(repo repo.AIChatRepo) *GetByIDUC {
	return &GetByIDUC{repo: repo}
}

func (uc *GetByIDUC) Execute(ctx context.Context, userID uint, id uint) (*models.AIChat, error) {
	if userID == 0 || id == 0 {
		return nil, errs.ErrInvalidInput
	}

	return uc.repo.Get(ctx, userID, id)
}
