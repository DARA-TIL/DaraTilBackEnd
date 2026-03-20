package userUC

import (
	"DaraTilBackendV2/internal/application/services"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type LvlUpUC struct {
	repo      repo.UserRepo
	publisher services.Publisher
}

func NewLvlUpUC(repo repo.UserRepo, pub services.Publisher) *LvlUpUC {
	return &LvlUpUC{repo: repo, publisher: pub}
}

func (u *LvlUpUC) Execute(ctx context.Context, userId uint, xpAdded int) models.LvlRet {
	lvlRet := u.repo.LvlUp(ctx, userId, xpAdded)
	if lvlRet.Err != nil {
		return lvlRet
	}
	if lvlRet.IsLvlUp {
		u.publisher.NotifySubscribers(ctx, services.Event{
			Action:     models.Level_upgraded,
			UserID:     userId,
			EntityType: models.UserEntityType,
			EntityID:   userId,
		})
	}
	return lvlRet
}
