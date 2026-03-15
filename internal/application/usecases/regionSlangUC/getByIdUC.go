package regionSlangUC

import (
	"DaraTilBackendV2/internal/application/services"
	"DaraTilBackendV2/internal/application/utils"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
	"errors"
)

type GetSlangResult struct {
	Slang  *models.RegionSlang
	Streak services.StreakUpdateResult
}

type GetByIDUC struct {
	repo            repo.RegionSlangRepo
	activityService *services.UserActivityService
}

func NewGetByIDUC(repo repo.RegionSlangRepo, ua *services.UserActivityService) *GetByIDUC {
	return &GetByIDUC{
		repo:            repo,
		activityService: ua,
	}
}
func (uc *GetByIDUC) Execute(ctx context.Context, id uint) (GetSlangResult, error) {
	sl, err := uc.repo.GetByID(ctx, id)
	ret := GetSlangResult{Slang: sl}
	userID, ok := utils.GetUserIDFromContext(ctx)
	if !ok {
		utils.ErrLoggerUserActivity(errors.New("cannot get user ID"))
		return ret, nil
	}
	str, err2 := uc.activityService.LogActivityWithStreak(ctx, models.Region_slang_opened, "region_slang", userID, id)
	if err2 != nil {
		utils.ErrLoggerUserActivity(err2)
	}
	ret.Streak = str
	return ret, err
}
