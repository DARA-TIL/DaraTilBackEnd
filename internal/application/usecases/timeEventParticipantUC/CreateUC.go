package timeEventParticipantUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type CreateUC struct {
	repo repo.TimeEventParticipantRepo
}

func NewCreateUC(repo repo.TimeEventParticipantRepo) *CreateUC {
	return &CreateUC{repo: repo}
}

func (uc *CreateUC) Execute(ctx context.Context, p models.TimeEventParticipant) (*models.TimeEventParticipant, error) {
	return uc.repo.Create(ctx, p)
}
