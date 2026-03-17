package userUC

import (
	"DaraTilBackendV2/internal/application/services"
	"DaraTilBackendV2/internal/application/utils"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type LvlUpUC struct {
	repo            repo.UserRepo
	activityService *services.UserActivityService
	publisher       services.Publisher
}

func NewLvlUpUC(repo repo.UserRepo, ua *services.UserActivityService, pub services.Publisher) *LvlUpUC {
	return &LvlUpUC{repo: repo, activityService: ua, publisher: pub}
}

func (u *LvlUpUC) Execute(ctx context.Context, userId uint, xpAdded int) models.LvlRet {
	lvlRet := u.repo.LvlUp(ctx, userId, xpAdded)
	if lvlRet.Err != nil {
		return lvlRet
	}
	if lvlRet.IsLvlUp {
		err := u.activityService.LogActivityWithoutStreak(ctx, models.Level_upgraded, "user", userId, userId)
		if err != nil {
			utils.ErrLoggerUserActivity(err)
		}
		u.publisher.NotifySubscribers(ctx, services.Event{
			Action: models.Level_upgraded,
			UserID: userId,
		})
	}
	return lvlRet
}
