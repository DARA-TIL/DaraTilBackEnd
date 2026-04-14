package repository

import (
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/errhandlers"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels/gormMappers"
	"context"

	"gorm.io/gorm"
)

type UserProfileRepository struct {
	db *gorm.DB
}

func NewUserProfileRepository(db *gorm.DB) *UserProfileRepository {
	return &UserProfileRepository{
		db: db,
	}
}

func (u *UserProfileRepository) Create(ctx context.Context, up models.CreateUserProfile) error {
	profile := gormModels.UserProfile{
		UserID: up.UserID,
	}
	err := u.db.WithContext(ctx).Create(&profile).Error
	if err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}

func (u *UserProfileRepository) GetByUserID(ctx context.Context, uid uint) (*models.UserProfile, error) {
	var profile gormModels.UserProfile
	err := u.db.WithContext(ctx).Preload("User.Streak").Preload("User.Progress").Preload("PinnedAchievements.Achievement.UserAchievements", "user_id = ?", uid).First(&profile, "user_id = ?", uid).Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	profileDom := gormMappers.UserProfileToDomain(profile)
	return &profileDom, nil
}

func (u *UserProfileRepository) UpdatePinnedAchievements(ctx context.Context, up models.UserProfileUpdate) error {
	return u.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if len(up.PinnedAchievementIDS) > 3 {
			return errs.ErrInvalidInput
		}
		var profile gormModels.UserProfile
		err := tx.Where("user_id = ?", up.UserID).First(&profile).Error
		if err != nil {
			return errhandlers.DBErrHandler(err)
		}
		var ua []gormModels.UserAchievement
		err = tx.Where("user_id = ? AND achieved = ?", up.UserID, true).
			Find(&ua).Error
		if err != nil {
			return errhandlers.DBErrHandler(err)
		}
		uaMap := make(map[uint]gormModels.UserAchievement)
		for _, u := range ua {
			uaMap[u.AchievementID] = u
		}
		seen := make(map[uint]bool)
		for _, id := range up.PinnedAchievementIDS {
			if seen[id] {
				return errs.ErrInvalidInput
			}
			seen[id] = true
			if _, ok := uaMap[id]; !ok {
				return errs.ErrInvalidInput
			}
		}
		err = tx.Unscoped().Where("user_id = ?", up.UserID).Delete(&gormModels.PinnedAchievement{}).Error
		if err != nil {
			return errhandlers.DBErrHandler(err)
		}
		newPinned := gormMappers.PinnedAchievementsFromIDs(up)
		if len(newPinned) > 0 {
			if err := tx.Create(&newPinned).Error; err != nil {
				return errhandlers.DBErrHandler(err)
			}
		} else {
			return errs.ErrInvalidInput
		}
		return nil
	})
}

func (u *UserProfileRepository) IncreaseWordsLearned(ctx context.Context, userID uint) error {
	if err := u.db.WithContext(ctx).UpdateColumn("words_learned", gorm.Expr("words_learned + ?", 1)).Error; err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}

func (u *UserProfileRepository) IncreaseLessonsCompleted(ctx context.Context, userID uint) error {
	if err := u.db.WithContext(ctx).UpdateColumn("lessons_completed", gorm.Expr("lessons_completed + ?", 1)).Error; err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}
