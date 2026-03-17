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
	publisher       services.Publisher
}

func NewGetByIDUC(repo repo.RegionSlangRepo, ua *services.UserActivityService, pub services.Publisher) *GetByIDUC {
	return &GetByIDUC{
		repo:            repo,
		activityService: ua,
		publisher:       pub,
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
	uc.publisher.NotifySubscribers(ctx, services.Event{
		Action: models.Region_slang_readed,
		UserID: userID,
	})
	str, err2 := uc.activityService.LogActivityWithStreak(ctx, models.Region_slang_readed, "region_slang", userID, id)
	if err2 != nil {
		utils.ErrLoggerUserActivity(err2)
	}
	ret.Streak = str
	return ret, err
}
