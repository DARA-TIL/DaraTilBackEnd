package folkloreUC

import (
	"DaraTilBackendV2/internal/application/services"
	"DaraTilBackendV2/internal/application/utils"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type ToggleLikeResult struct {
	Folklore *models.Folklore
	Liked    bool
	Streak   services.StreakUpdateResult
}

type ToggleLikeUC struct {
	repo                repo.FolkloreRepo
	userActivityService *services.UserActivityService
}

func NewToggleLikeUC(repo repo.FolkloreRepo, uas *services.UserActivityService) *ToggleLikeUC {
	return &ToggleLikeUC{repo: repo, userActivityService: uas}
}

func (uc *ToggleLikeUC) Execute(ctx context.Context, folkloreID, userID uint) (*ToggleLikeResult, error) {
	folk, liked, err := uc.repo.ToggleLike(ctx, folkloreID, userID)
	res := &ToggleLikeResult{
		Folklore: folk,
		Liked:    liked,
	}
	if err == nil {
		var act models.Actions
		if liked {
			act = models.Folklore_liked
		} else {
			act = models.Folklore_disliked
		}
		streak, err := uc.userActivityService.LogActivity(ctx, act, "folklore", userID, folkloreID)
		if err != nil {
			utils.ErrLoggerUserActivity(err)
		}
		res.Streak = streak
	}
	if err != nil {
		return nil, err
	}
	return res, err
}
