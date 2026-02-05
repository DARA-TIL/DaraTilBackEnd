package repository

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/errhandlers"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels/gormMappers"
	"context"
	"log"

	"gorm.io/gorm"
)

type UserRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (u *UserRepository) Create(ctx context.Context, user models.User) (*models.User, error) {
	userGorm := gormMappers.UserToGormModel(user)
	err := u.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&userGorm).Error; err != nil {
			return err
		}
		userProg := gormModels.UserProgress{
			UserID: userGorm.ID,
		}
		if err := tx.Create(&userProg).Error; err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	var userWithProgress gormModels.User
	err = u.db.WithContext(ctx).Preload("Progress").Where("id = ?", userGorm.ID).First(&userWithProgress).Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	user = gormMappers.GormUserToDomain(userWithProgress)
	return &user, nil
}

func (u *UserRepository) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	var userGorm gormModels.User
	if err := u.db.WithContext(ctx).Preload("Progress").Where("email = ?", email).First(&userGorm).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	user := gormMappers.GormUserToDomain(userGorm)
	return &user, nil
}

func (u *UserRepository) GetByID(ctx context.Context, id int) (*models.User, error) {
	var userGorm gormModels.User
	if err := u.db.WithContext(ctx).Preload("Progress").Where("id = ?", id).First(&userGorm).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	user := gormMappers.GormUserToDomain(userGorm)
	return &user, nil
}

func (u *UserRepository) Update(ctx context.Context, id int, upd models.UserUpdatableFields) (*models.User, error) {
	updates := make(map[string]any)
	if upd.Password != nil {
		updates["password"] = *upd.Password
	}
	if upd.Role != nil {
		updates["role"] = *upd.Role
	}
	if upd.Username != nil {
		updates["username"] = *upd.Username
	}
	if upd.Avatar != nil {
		updates["avatar"] = *upd.Avatar
	}
	if err := u.db.WithContext(ctx).Model(&gormModels.User{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	return u.GetByID(ctx, id)
}

func (u *UserRepository) GetAll(ctx context.Context) ([]models.User, error) {
	var users []gormModels.User
	if err := u.db.WithContext(ctx).Preload("Progress").Find(&users).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	var domUsers []models.User
	for _, user := range users {
		domUsers = append(domUsers, gormMappers.GormUserToDomain(user))
	}
	return domUsers, nil
}
func (u *UserRepository) LvlUp(ctx context.Context, userId, xpAdded int) (int, int, bool, *models.User, error) {
	var prevLevel, prevXp int
	var isLvlUp bool
	var user gormModels.User
	err := u.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.WithContext(ctx).Preload("Progress").First(&user, userId).Error; err != nil {
			return err
		}
		progress := user.Progress
		prevLevel = progress.Level
		prevXp = progress.XpTotal
		progress.XpTotal += xpAdded
		isLvlUp = false
		if progress.XpTotal >= progress.XpForNextLevel {
			for progress.XpTotal >= progress.XpForNextLevel {
				progress.XpTotal = progress.XpTotal - progress.XpForNextLevel
				progress.XpForNextLevel += 100 * progress.Level
				progress.Level++
				log.Printf("[FOLKLORE][LevelUp] Level up for: %+v", user.Email)
			}
			isLvlUp = true
		}
		if err := tx.WithContext(ctx).Save(&progress).Error; err != nil {
			return errhandlers.DBErrHandler(err)
		}
		return nil
	})
	if err != nil {
		return 0, 0, false, nil, err
	}
	userDom := gormMappers.GormUserToDomain(user)
	return prevLevel, prevXp, isLvlUp, &userDom, nil
}
