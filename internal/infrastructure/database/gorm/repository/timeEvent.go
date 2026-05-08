package repository

import (
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/errhandlers"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels/gormMappers"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"context"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"
)

type TimeEventRepository struct {
	db *gorm.DB
}

func NewTimeEventRepository(db *gorm.DB) *TimeEventRepository {
	return &TimeEventRepository{db: db}
}

func (t *TimeEventRepository) Create(ctx context.Context, event models.TimeEvent) (*models.TimeEvent, error) {
	gormEvent := gormMappers.TimeEventToGormModel(event)
	err := t.db.WithContext(ctx).Create(&gormEvent).Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	event = gormMappers.GormTimeEventToDomainModel(gormEvent)
	return &event, nil
}

func (t *TimeEventRepository) Update(ctx context.Context, event models.TimeEvent) (*models.TimeEvent, error) {
	gormEvent := gormMappers.TimeEventToGormModel(event)
	err := t.db.WithContext(ctx).Model(&gormEvent).Where("id = ?", event.ID).Updates(&gormEvent).Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	err = t.db.WithContext(ctx).Model(&gormModels.TimeEvent{}).Where("id = ?", event.ID).First(&gormEvent).Error
	if err != nil {
		return nil, nil
	}
	event = gormMappers.GormTimeEventToDomainModel(gormEvent)
	return &event, nil
}

func (t *TimeEventRepository) Delete(ctx context.Context, id uint) error {
	err := t.db.WithContext(ctx).Unscoped().Where("id = ?", id).Delete(&gormModels.TimeEvent{}).Error
	if err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}

func (t *TimeEventRepository) GetByID(ctx context.Context, id uint) (*models.TimeEvent, error) {
	var gormEvent gormModels.TimeEvent
	err := t.db.WithContext(ctx).
		Preload("Participants").
		Preload("Participants.User").
		Preload("Participants.User.Progress").
		Preload("Participants.User.Streak").
		First(&gormEvent, id).
		Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	event := gormMappers.GormTimeEventToDomainModel(gormEvent)
	return &event, nil
}

func (t *TimeEventRepository) GetAll(
	ctx context.Context,
	params models.TimeEventParams,
) ([]models.TimeEvent, error) {
	gormEvents := make([]gormModels.TimeEvent, 0)

	query := t.db.WithContext(ctx).Model(&gormModels.TimeEvent{})

	if params.EventType != nil {
		query = query.Where("event_type = ?", string(*params.EventType))
	}

	if params.Status != nil {
		query = query.Where("status = ?", string(*params.Status))
	}

	if params.StartDateFrom != nil {
		query = query.Where("start_date >= ?", *params.StartDateFrom)
	}

	if params.StartDateTo != nil {
		query = query.Where("start_date <= ?", *params.StartDateTo)
	}

	if params.EndDateFrom != nil {
		query = query.Where("end_date >= ?", *params.EndDateFrom)
	}

	if params.EndDateTo != nil {
		query = query.Where("end_date <= ?", *params.EndDateTo)
	}
	if params.IsWeekly != nil {
		query = query.Where("is_weekly = ?", *params.IsWeekly)
	}

	err := query.Find(&gormEvents).Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}

	if len(gormEvents) == 0 {
		return []models.TimeEvent{}, nil
	}

	events := gormMappers.GormTimeEventsToDomainModel(gormEvents)
	return events, nil
}

func (t *TimeEventRepository) ChangeEventStatus(ctx context.Context, id uint, status models.TimeEventStatus) error {
	isActive := false
	switch status {
	case models.Started:
		isActive = true
	default:
		isActive = false
	}
	var gormEvent gormModels.TimeEvent
	if err := t.db.WithContext(ctx).First(&gormEvent, id).Error; err != nil {
		return errhandlers.DBErrHandler(err)
	}
	if gormEvent.Status == models.Ended {
		return errs.ErrForbidden
	}

	err := t.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&gormModels.TimeEvent{}).Where("id = ?", id).Update("status", status).Error; err != nil {
			return err
		}
		res := tx.Model(&gormModels.TimeEventParticipant{}).Where("time_event_id = ?", id)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected != 0 {
			if err := tx.Model(&gormModels.TimeEventParticipant{}).Where("time_event_id = ?", id).Update("is_active", isActive).Error; err != nil {
				return err
			}
			return nil
		}
		return nil
	})
	if err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}

func (t *TimeEventRepository) StartDueEvents(ctx context.Context) error {
	now := time.Now()
	err := t.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.
			Model(&gormModels.TimeEvent{}).
			Where("status = ?", string(models.Waiting)).
			Where("start_date <= ?", now).
			Update("status", models.Started)
		if res.Error != nil {
			return res.Error
		}
		logger.Info("Started Events:", zap.Int64("count:", res.RowsAffected))
		return nil
	})
	if err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}
