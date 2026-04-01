package folkloreUC

import (
	"DaraTilBackendV2/internal/application/services"
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
	repo      repo.FolkloreRepo
	publisher services.Publisher
}

func NewToggleLikeUC(repo repo.FolkloreRepo, pub services.Publisher) *ToggleLikeUC {
	return &ToggleLikeUC{repo: repo, publisher: pub}
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
		uc.publisher.Publish(ctx, services.Event{
			Action:     act,
			UserID:     userID,
			EntityID:   folkloreID,
			EntityType: models.FolkloreEntityType,
		})
	}
	if err != nil {
		return nil, err
	}
	return res, err
}
