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
	GetAll(ctx context.Context, params models.TimeEventParams) ([]models.TimeEvent, error)
	ChangeEventStatus(ctx context.Context, id uint, status models.TimeEventStatus) error
	StartDueEvents(ctx context.Context) error
}

type TimeEventParticipantRepo interface {
	Create(ctx context.Context, p models.TimeEventParticipant) (*models.TimeEventParticipant, error)
	Update(ctx context.Context, p models.TimeEventParticipant) (*models.TimeEventParticipant, error)
	GetEventParticipants(ctx context.Context, eventID uint, limit int) ([]models.TimeEventParticipant, error)
	Delete(ctx context.Context, id uint) error
	GetEventParticipantByID(ctx context.Context, id uint) (*models.TimeEventParticipant, error)
	GetEventParticipantByUserAndEventID(ctx context.Context, userID, eventID uint) (*models.TimeEventParticipant, error)
	UpdatePlaces(ctx context.Context, eventID uint) error
	IncreaseStat(ctx context.Context, id uint) error
}
