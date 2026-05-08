package repository

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/errhandlers"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels/gormMappers"
	"context"

	"gorm.io/gorm"
)

type TimeEventParticipantRepository struct {
	db *gorm.DB
}

func NewTimeEventParticipantRepository(db *gorm.DB) *TimeEventParticipantRepository {
	return &TimeEventParticipantRepository{db: db}
}

func (t *TimeEventParticipantRepository) Create(ctx context.Context, p models.TimeEventParticipant) (*models.TimeEventParticipant, error) {
	gormParticipant := gormMappers.TimeEventParticipantToGormModel(p)
	err := t.db.WithContext(ctx).Create(&gormParticipant).Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	p = gormMappers.GormTimeEventParticipantToDomainModel(gormParticipant)
	return &p, nil
}

func (t *TimeEventParticipantRepository) Update(ctx context.Context, p models.TimeEventParticipant) (*models.TimeEventParticipant, error) {
	gormParticipant := gormMappers.TimeEventParticipantToGormModel(p)
	err := t.db.WithContext(ctx).Model(&gormParticipant).Updates(gormParticipant).Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	err = t.db.WithContext(ctx).Model(&gormParticipant).First(&gormParticipant, "id = ?", p.ID).Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	p = gormMappers.GormTimeEventParticipantToDomainModel(gormParticipant)
	return &p, nil
}

func (t *TimeEventParticipantRepository) GetEventParticipants(ctx context.Context, eventID uint, limit int) ([]models.TimeEventParticipant, error) {
	var gormParticipants []gormModels.TimeEventParticipant
	if err := t.db.WithContext(ctx).
		Preload("User").
		Preload("User.Progress").
		Preload("User.Streak").
		Limit(limit).
		Order("count DESC").Find(&gormParticipants, "time_event_id = ?", eventID).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	participants := gormMappers.GormTimeEventParticipantsToDomainModel(gormParticipants)
	return participants, nil
}

func (t *TimeEventParticipantRepository) Delete(ctx context.Context, id uint) error {
	err := t.db.WithContext(ctx).Unscoped().Delete(&gormModels.TimeEventParticipant{}, "id = ?", id).Error
	if err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}

func (t *TimeEventParticipantRepository) GetEventParticipantByID(ctx context.Context, id uint) (*models.TimeEventParticipant, error) {
	var gormParticipant gormModels.TimeEventParticipant
	if err := t.db.WithContext(ctx).
		Preload("User").
		Preload("User.Progress").
		Preload("User.Streak").
		First(&gormParticipant, "id = ?", id).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	p := gormMappers.GormTimeEventParticipantToDomainModel(gormParticipant)
	return &p, nil
}

func (t *TimeEventParticipantRepository) GetEventParticipantByUserAndEventID(ctx context.Context, userID, eventID uint) (*models.TimeEventParticipant, error) {
	var gormParticipant gormModels.TimeEventParticipant
	if err := t.db.WithContext(ctx).
		Preload("User").
		Preload("User.Progress").
		Preload("User.Streak").
		First(&gormParticipant, "user_id = ? AND time_event_id = ?", userID, eventID).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	p := gormMappers.GormTimeEventParticipantToDomainModel(gormParticipant)
	return &p, nil
}

func (t *TimeEventParticipantRepository) UpdatePlaces(ctx context.Context, eventID uint) error {
	var event gormModels.TimeEvent
	if err := t.db.WithContext(ctx).First(&event, "id = ?", eventID).Error; err != nil {
		return errhandlers.DBErrHandler(err)
	}
	var gormParticipants []gormModels.TimeEventParticipant
	if err := t.db.WithContext(ctx).Order("count DESC").Find(&gormParticipants, "time_event_id = ?", event.ID).Error; err != nil {
		return errhandlers.DBErrHandler(err)
	}
	count := 1
	err := t.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, participant := range gormParticipants {
			if err := tx.Model(&gormModels.TimeEventParticipant{}).Where("id = ?", participant.ID).Update("place", count).Error; err != nil {
				return err
			}
			count++
		}
		return nil
	})
	if err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}

func (t *TimeEventParticipantRepository) IncreaseStat(ctx context.Context, id uint) error {
	var gormParticipant gormModels.TimeEventParticipant
	err := t.db.WithContext(ctx).
		Model(&gormParticipant).
		Where("id = ?", id).
		Update("count", gorm.Expr("count + ?", 1)).Error
	if err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}
