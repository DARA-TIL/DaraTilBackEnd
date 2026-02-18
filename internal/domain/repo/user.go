package repo

import (
	"DaraTilBackendV2/internal/domain/models"
	"context"
)

type UserRepo interface {
	Create(ctx context.Context, user models.User) (*models.User, error)
	GetByEmail(ctx context.Context, email string) (*models.User, error)
	GetByUsername(ctx context.Context, username string) ([]models.User, error)
	GetByID(ctx context.Context, id uint) (*models.User, error)
	Update(ctx context.Context, id uint, upd models.UserUpdatableFields) (*models.User, error)
	GetAll(ctx context.Context) ([]models.User, error)
	LvlUp(ctx context.Context, userId uint, xpAdded int) models.LvlRet //prevLvl,prevXp,isLvlUp,UserCur, err
}
