package repository

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/errhandlers"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels/gormMappers"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"context"
	"errors"

	"go.uber.org/zap"
	"gorm.io/gorm"
)

type UserAchievementRepository struct {
	db *gorm.DB
}

func NewUserAchievementRepository(db *gorm.DB) *UserAchievementRepository {
	return &UserAchievementRepository{db: db}
}

func (u UserAchievementRepository) Create(ctx context.Context, ua models.UserAchievement) error {
	gormUa := gormMappers.UserAchievementToGormModel(ua)
	if err := u.db.WithContext(ctx).Create(&gormUa).Error; err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}

func (u UserAchievementRepository) Update(ctx context.Context, ua models.UserAchievement) error {
	gormUa := gormMappers.UserAchievementToGormModel(ua)
	if err := u.db.WithContext(ctx).Model(&gormModels.UserAchievement{}).Where("id = ?", ua.ID).Updates(&gormUa).Error; err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}

func (u UserAchievementRepository) IncrementQuantity(ctx context.Context, userID uint, action models.Actions) ([]models.UserAchievement, error) {
	var updated []gormModels.UserAchievement
	err := u.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		err := tx.Exec(
			`UPDATE user_achievements ua
				 SET quantity = ua.quantity + 1
				FROM achievements a
				 Where a.id = ua.achievement_id
				AND a.action = ?
				AND ua.user_id = ?
				AND ua.achieved = ?`, action, userID, false).Error
		if err != nil {
			return err
		}
		err = tx.Raw(
			`UPDATE user_achievements ua
				SET achieved = true
				FROM achievements a
				Where a.id = ua.achievement_id
				AND a.action = ?
				AND ua.user_id = ?
				AND ua.achieved = ?
				AND ua.quantity >= a.quantity
				RETURNING ua.id, ua.user_id, ua.achievement_id, ua.quantity, ua.achieved`, action, userID, false).Scan(&updated).Error
		if err != nil {
			logger.Error("error while increasing achievement quantity", zap.Error(err))
			return errhandlers.DBErrHandler(err)
		}
		return nil
	})
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	updDom := gormMappers.GormUserAchievementsToDomain(updated)
	return updDom, nil
}

func (u UserAchievementRepository) Delete(ctx context.Context, id uint) error {
	if err := u.db.WithContext(ctx).Unscoped().Delete(&gormModels.UserAchievement{}, id).Error; err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}

func (u UserAchievementRepository) CreateMissingUserAchievements(ctx context.Context, userID uint, action models.Actions) error {
	err := u.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var gormAchievements []gormModels.Achievement
		err := tx.Where("action = ?", action).Find(&gormAchievements).Error
		if err != nil {
			return err
		}
		for _, a := range gormAchievements {
			var ua gormModels.UserAchievement
			err = tx.Where("achievement_id = ? AND user_id = ?", a.ID, userID).First(&ua).Error
			if errors.Is(err, gorm.ErrRecordNotFound) {
				err := tx.Create(&gormModels.UserAchievement{
					UserID:        userID,
					AchievementID: a.ID,
				}).Error
				if err != nil {
					return err
				}
				continue
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}

func (u UserAchievementRepository) GetByUserID(ctx context.Context, userID uint) ([]models.UserAchievement, error) {
	var gormUserAchievements []gormModels.UserAchievement
	err := u.db.WithContext(ctx).Where("user_id = ?", userID).Find(&gormUserAchievements).Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	ua := gormMappers.GormUserAchievementsToDomain(gormUserAchievements)
	return ua, nil
}

func (u UserAchievementRepository) GetByID(ctx context.Context, id uint) (*models.UserAchievement, error) {
	var gormUserAchievement gormModels.UserAchievement
	err := u.db.WithContext(ctx).Where("id = ?", id).First(&gormUserAchievement).Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	ua := gormMappers.GormUserAchievementToDomain(gormUserAchievement)
	return &ua, nil
}
