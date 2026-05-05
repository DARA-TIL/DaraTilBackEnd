package repository

import (
	"DaraTilBackendV2/internal/domain/models"
	"context"

	"gorm.io/gorm"
)

type TimeEventRepository struct {
	db *gorm.DB
}

func NewTimeEventRepository(db *gorm.DB) *TimeEventRepository {
	return &TimeEventRepository{db: db}
}

func (t *TimeEventRepository) Create(ctx context.Context, event models.TimeEvent) (*models.TimeEvent, error) {
	//TODO implement me
	panic("implement me")
}

func (t *TimeEventRepository) Update(ctx context.Context, event models.TimeEvent) (*models.TimeEvent, error) {
	//TODO implement me
	panic("implement me")
}

func (t *TimeEventRepository) Delete(ctx context.Context, id uint) error {
	//TODO implement me
	panic("implement me")
}

func (t *TimeEventRepository) GetByID(ctx context.Context, id uint) (*models.TimeEvent, error) {
	//TODO implement me
	panic("implement me")
}

func (t *TimeEventRepository) GetAll(ctx context.Context) ([]models.TimeEvent, error) {
	//TODO implement me
	panic("implement me")
}
