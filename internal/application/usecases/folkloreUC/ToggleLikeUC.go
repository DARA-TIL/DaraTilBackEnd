package folkloreUC

import (
	"DaraTilBackendV2/internal/application/services"
	"DaraTilBackendV2/internal/application/utils"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type ToggleLikeUC struct {
	repo                repo.FolkloreRepo
	userActivityService *services.UserActivityService
}

func NewToggleLikeUC(repo repo.FolkloreRepo, uas *services.UserActivityService) *ToggleLikeUC {
	return &ToggleLikeUC{repo: repo, userActivityService: uas}
}

func (uc *ToggleLikeUC) Execute(ctx context.Context, folkloreID, userID uint) (*models.Folklore, bool, error) {
	folk, liked, err := uc.repo.ToggleLike(ctx, folkloreID, userID)
	if err == nil {
		var act models.Actions
		if liked {
			act = models.Folklore_liked
		} else {
			act = models.Folklore_disliked
		}
		utils.LoggerUserActivity(userID, folkloreID, "folklore", string(act))
		err = uc.userActivityService.LogActivity(ctx, act, "folklore", userID, folkloreID)
		if err != nil {
			utils.ErrLoggerUserActivity(err)
		}
	}
	return folk, liked, err
}
