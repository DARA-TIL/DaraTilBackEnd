package aiChatUC

import (
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetAllUC struct {
	repo repo.AIChatRepo
}

func NewGetAllUC(repo repo.AIChatRepo) *GetAllUC {
	return &GetAllUC{repo: repo}
}

func (uc *GetAllUC) Execute(ctx context.Context, userID uint) ([]models.AIChat, error) {
	if userID == 0 {
		return nil, errs.ErrInvalidInput
	}

	return uc.repo.GetAll(ctx, userID)
}
