package repository

import (
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/errhandlers"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels/gormMappers"
	"context"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type NotificationRepository struct {
	db *gorm.DB
}

func NewNotificationRepository(db *gorm.DB) *NotificationRepository {
	return &NotificationRepository{db: db}
}

func (n *NotificationRepository) Create(ctx context.Context, notification models.Notification) (*models.Notification, error) {
	gormNotif := gormMappers.NotificationToGormModel(notification)
	err := n.db.WithContext(ctx).Create(&gormNotif).Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	notification = gormMappers.GormNotificationToDomainModel(gormNotif)
	return &notification, nil
}

func (n *NotificationRepository) GetNotificationByID(ctx context.Context, notificationID, userID uint) (*models.Notification, error) {
	var gormNotif gormModels.Notification
	err := n.db.WithContext(ctx).Preload("Reads", "user_id = ?", userID).First(&gormNotif, notificationID).Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	if gormNotif.UserID != nil {
		if *gormNotif.UserID != userID {
			return nil, errs.ErrForbidden
		}
	}
	notif := gormMappers.GormNotificationToDomainModel(gormNotif)
	now := time.Now()
	if len(gormNotif.Reads) == 0 {
		notifRead := gormModels.NotificationRead{
			NotificationID: gormNotif.ID,
			UserID:         userID,
			ReadAt:         &now,
		}
		err = n.db.WithContext(ctx).Create(&notifRead).Error
		if err != nil {
			//Failed to read notif
			return &notif, nil
		}
	}
	return &notif, nil
}

func (n *NotificationRepository) GetAllNotifications(
	ctx context.Context,
	params models.NotificationParams,
) ([]models.Notification, error) {
	var gormNotifs []gormModels.Notification

	query := n.db.WithContext(ctx).
		Model(&gormModels.Notification{})

	if params.UserID != nil {
		query = query.
			Joins(`
				LEFT JOIN notification_reads 
				ON notification_reads.notification_id = notifications.id 
				AND notification_reads.user_id = ?
			`, *params.UserID).
			Where(
				"(notifications.user_id = ? OR notifications.scope = ?)",
				*params.UserID,
				models.NotificationScopeGlobal,
			).
			Where(
				"(notification_reads.id IS NULL OR notification_reads.is_active = ?)",
				true,
			)
	}

	if params.Scope != nil {
		query = query.Where("notifications.scope = ?", *params.Scope)
	}

	if params.Type != nil {
		query = query.Where("notifications.type = ?", *params.Type)
	}

	if params.NotSeen != nil && *params.NotSeen {
		if params.UserID == nil {
			return nil, errs.ErrBadRequest
		}

		query = query.Where(
			"(notification_reads.id IS NULL OR notification_reads.read_at IS NULL)",
		)
	}
	query = query.Where("notifications.is_active = ?", true)
	query = query.Order("notifications.created_at DESC")

	if params.Limit != nil {
		query = query.Limit(*params.Limit)
	}

	if params.UserID != nil {
		query = query.Preload("Reads", "user_id = ?", *params.UserID)
	} else {
		query = query.Preload("Reads")
	}

	err := query.Find(&gormNotifs).Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}

	notifs := gormMappers.GormNotificationsToDomainModel(gormNotifs)
	return notifs, nil
}

func (n *NotificationRepository) Update(
	ctx context.Context,
	params models.UpdateNotificationParams,
) (*models.Notification, error) {
	if params.ID == 0 {
		return nil, errs.ErrInvalidInput
	}

	updates := map[string]interface{}{}

	if params.Title != nil {
		updates["title"] = *params.Title
	}

	if params.Message != nil {
		updates["message"] = *params.Message
	}

	if params.Type != nil {
		updates["type"] = string(*params.Type)
	}

	if params.Scope != nil {
		updates["scope"] = string(*params.Scope)
	}

	if params.IsActive != nil {
		updates["is_active"] = *params.IsActive
	}

	if len(updates) == 0 {
		return nil, errs.ErrInvalidInput
	}

	res := n.db.WithContext(ctx).
		Model(&gormModels.Notification{}).
		Where("id = ?", params.ID).
		Updates(updates)

	if res.Error != nil {
		return nil, errhandlers.DBErrHandler(res.Error)
	}

	if res.RowsAffected == 0 {
		return nil, errs.ErrNotFound
	}

	var gormNotif gormModels.Notification

	err := n.db.WithContext(ctx).
		Preload("Reads").
		First(&gormNotif, params.ID).Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}

	notification := gormMappers.GormNotificationToDomainModel(gormNotif)
	return &notification, nil
}

func (n *NotificationRepository) Delete(ctx context.Context, notificationID uint) error {
	err := n.db.WithContext(ctx).Unscoped().Delete(&gormModels.Notification{}, notificationID).Error
	if err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}
func (n *NotificationRepository) CreateReadNotifications(
	ctx context.Context,
	notifications []models.Notification,
	userID uint,
) error {
	if len(notifications) == 0 {
		return nil
	}

	err := n.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		now := time.Now()

		reads := make([]gormModels.NotificationRead, 0, len(notifications))

		for _, notif := range notifications {
			if notif.ID == 0 {
				continue
			}

			if len(notif.Reads) != 0 {
				continue
			}

			reads = append(reads, gormModels.NotificationRead{
				NotificationID: notif.ID,
				UserID:         userID,
				ReadAt:         &now,
			})
		}

		if len(reads) == 0 {
			return nil
		}

		return tx.
			Clauses(clause.OnConflict{
				Columns: []clause.Column{
					{Name: "notification_id"},
					{Name: "user_id"},
				},
				DoNothing: true,
			}).
			Create(&reads).Error
	})

	if err != nil {
		return errhandlers.DBErrHandler(err)
	}

	return nil
}

func (n *NotificationRepository) DeleteNotificationForUser(ctx context.Context, notifID, userID uint) error {
	err := n.db.WithContext(ctx).Model(&gormModels.NotificationRead{}).Where("notification_id = ? AND user_id = ? AND is_active= ?", notifID, userID, true).Update("is_active", false).Error
	if err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}
func (n *NotificationRepository) DeleteAllNotificationsForUser(ctx context.Context, userID uint) error {
	err := n.db.WithContext(ctx).Model(&gormModels.NotificationRead{}).Where("user_id = ? AND is_active = ?", userID, true).Update("is_active", false).Error
	if err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}
