package repo

import (
	"DaraTilBackendV2/internal/domain/models"
	"context"
)

type TimeEventRepo interface {
	Create(ctx context.Context, event models.TimeEvent) (*models.TimeEvent, error)
	Update(ctx context.Context, event models.TimeEvent) (*models.TimeEvent, error)
	Delete(ctx context.Context, id uint) error
	GetByID(ctx context.Context, id uint) (*models.TimeEvent, error)
	GetAll(ctx context.Context) ([]models.TimeEvent, error)
}

type TimeEventParticipant interface {
	Create(ctx context.Context, event models.TimeEventParticipant) (*models.TimeEventParticipant, error)
	Update(ctx context.Context, event models.TimeEventParticipant) (*models.TimeEventParticipant, error)
	GetEventParticipants(ctx context.Context, eventID uint) ([]models.TimeEventParticipant, error)
	Delete(ctx context.Context, id uint) error
	GetEventParticipantByID(ctx context.Context, id uint) (*models.TimeEventParticipant, error)
	RewardParticipants(ctx context.Context, eventID uint) ([]models.TimeEventParticipant, error)
}
