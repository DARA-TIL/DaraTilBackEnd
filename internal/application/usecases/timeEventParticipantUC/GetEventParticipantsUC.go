package timeEventParticipantUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetEventParticipantsUC struct {
	repo repo.TimeEventParticipantRepo
}

func NewGetEventParticipantsUC(repo repo.TimeEventParticipantRepo) *GetEventParticipantsUC {
	return &GetEventParticipantsUC{
		repo: repo,
	}
}

func (uc *GetEventParticipantsUC) Execute(ctx context.Context, id uint, limit int) ([]models.TimeEventParticipant, error) {
	return uc.repo.GetEventParticipants(ctx, id, limit)
}
