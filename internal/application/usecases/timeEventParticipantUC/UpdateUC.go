package timeEventParticipantUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type UpdateUC struct {
	repo repo.TimeEventParticipantRepo
}

func NewUpdateUC(repo repo.TimeEventParticipantRepo) *UpdateUC {
	return &UpdateUC{repo: repo}
}
func (uc *UpdateUC) Execute(ctx context.Context, p models.TimeEventParticipant) (*models.TimeEventParticipant, error) {
	return uc.repo.Update(ctx, p)
}
