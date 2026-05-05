package repository

import (
	"DaraTilBackendV2/internal/domain/models"
	"context"

	"gorm.io/gorm"
)

type TimeEventParticipantRepository struct {
	db *gorm.DB
}

func NewTimeEventParticipantRepository(db *gorm.DB) *TimeEventParticipantRepository {
	return &TimeEventParticipantRepository{db: db}
}

func (t TimeEventParticipantRepository) Create(ctx context.Context, event models.TimeEventParticipant) (*models.TimeEventParticipant, error) {
	//TODO implement me
	panic("implement me")
}

func (t TimeEventParticipantRepository) Update(ctx context.Context, event models.TimeEventParticipant) (*models.TimeEventParticipant, error) {
	//TODO implement me
	panic("implement me")
}

func (t TimeEventParticipantRepository) GetEventParticipants(ctx context.Context, eventID uint) ([]models.TimeEventParticipant, error) {
	//TODO implement me
	panic("implement me")
}

func (t TimeEventParticipantRepository) Delete(ctx context.Context, id uint) error {
	//TODO implement me
	panic("implement me")
}

func (t TimeEventParticipantRepository) GetEventParticipantByID(ctx context.Context, id uint) (*models.TimeEventParticipant, error) {
	//TODO implement me
	panic("implement me")
}

func (t TimeEventParticipantRepository) RewardParticipants(ctx context.Context, eventID uint) ([]models.TimeEventParticipant, error) {
	//TODO implement me
	panic("implement me")
}
