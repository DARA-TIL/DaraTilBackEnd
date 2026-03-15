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
}

func NewLvlUpUC(repo repo.UserRepo, ua *services.UserActivityService) *LvlUpUC {
	return &LvlUpUC{repo: repo, activityService: ua}
}

func (u *LvlUpUC) Execute(ctx context.Context, userId uint, xpAdded int) models.LvlRet {
	err := u.activityService.LogActivityWithoutStreak(ctx, models.Level_upgraded, "user", userId, userId)
	if err != nil {
		utils.ErrLoggerUserActivity(err)
	}
	return u.repo.LvlUp(ctx, userId, xpAdded)
}
