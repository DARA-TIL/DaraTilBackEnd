package regionTraditionsUC

import (
	"DaraTilBackendV2/internal/application/services"
	"DaraTilBackendV2/internal/application/utils"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"context"
)

type GetTraditionResult struct {
	Tradition *models.RegionTraditions
	Streak    services.StreakUpdateResult
}

type GetByIDUC struct {
	repo            repo.RegionTraditionRepo
	activityService *services.UserActivityService
}

func NewGetByIDUC(repo repo.RegionTraditionRepo, ua *services.UserActivityService) *GetByIDUC {
	return &GetByIDUC{repo: repo, activityService: ua}
}
func (uc *GetByIDUC) Execute(ctx context.Context, id uint) (GetTraditionResult, error) {
	tr, err := uc.repo.GetByID(ctx, id)
	resp := GetTraditionResult{
		Tradition: tr,
	}
	userID, ok := utils.GetUserIDFromContext(ctx)
	if !ok {
		logger.Warn("userId not found in context")
		return resp, nil
	}
	str, err := uc.activityService.LogActivityWithStreak(ctx, models.Region_tradition_opened, "region_tradition", userID, id)
	resp.Streak = str
	return resp, err
}
