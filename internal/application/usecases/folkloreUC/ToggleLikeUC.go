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
	publisher           services.Publisher
}

func NewToggleLikeUC(repo repo.FolkloreRepo, uas *services.UserActivityService, pub services.Publisher) *ToggleLikeUC {
	return &ToggleLikeUC{repo: repo, userActivityService: uas, publisher: pub}
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
		uc.publisher.NotifySubscribers(ctx, services.Event{
			Action: act,
			UserID: userID,
		})
		streak, err := uc.userActivityService.LogActivityWithStreak(ctx, act, "folklore", userID, folkloreID)
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
