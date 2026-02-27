package folkloreUC

import (
	"DaraTilBackendV2/internal/application/services"
	"DaraTilBackendV2/internal/application/utils"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"context"
)

type GetFolkloreResult struct {
	Folklore *models.Folklore
	Streak   services.StreakUpdateResult
}

type GetByIDUC struct {
	repo                repo.FolkloreRepo
	userActivityService *services.UserActivityService
}

func NewGetByFolkloreIDUC(repo repo.FolkloreRepo, uaService *services.UserActivityService) *GetByIDUC {
	return &GetByIDUC{
		repo:                repo,
		userActivityService: uaService,
	}
}
func (uc *GetByIDUC) Execute(ctx context.Context, folkloreID uint) (*GetFolkloreResult, error) {
	folk, err := uc.repo.GetByID(ctx, folkloreID)
	if err != nil {
		return nil, err
	}
	res := &GetFolkloreResult{Folklore: folk}
	userID, ok := utils.GetUserIDFromContext(ctx)
	if !ok {
		logger.Warn("Failed to log user activity: UserID not found in context")
		return res, nil
	}
	streak, err := uc.userActivityService.LogActivity(ctx, models.Folklore_readed, "folklore", userID, folkloreID)
	if err != nil {
		utils.ErrLoggerUserActivity(err)
		return nil, err
	}
	res.Streak = streak
	return res, nil
}
