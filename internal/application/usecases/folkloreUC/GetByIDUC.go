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
	repo      repo.FolkloreRepo
	Publisher services.Publisher
}

func NewGetByFolkloreIDUC(repo repo.FolkloreRepo, publisher services.Publisher) *GetByIDUC {
	return &GetByIDUC{
		repo:      repo,
		Publisher: publisher,
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
	event := services.Event{
		Action:     models.Folklore_readed,
		UserID:     userID,
		EntityID:   folkloreID,
		EntityType: models.FolkloreEntityType,
	}
	uc.Publisher.NotifySubscribers(ctx, event)
	return res, nil
}
