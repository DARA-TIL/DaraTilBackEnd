package timeEventParticipantUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetEventParticipantUC struct {
	repo repo.TimeEventParticipantRepo
}

func NewGetEventParticipantUC(repo repo.TimeEventParticipantRepo) *GetEventParticipantUC {
	return &GetEventParticipantUC{repo: repo}
}

func (uc *GetEventParticipantUC) Execute(ctx context.Context, id uint) (*models.TimeEventParticipant, error) {
	return uc.repo.GetEventParticipantByID(ctx, id)
}
