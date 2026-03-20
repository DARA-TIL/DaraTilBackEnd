package services

import (
	"DaraTilBackendV2/internal/application/utils"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type UserActivityService struct {
	repo repo.UserActivityRepo
}

func NewUserActivityService(repo repo.UserActivityRepo) *UserActivityService {
	return &UserActivityService{repo: repo}
}

func (s *UserActivityService) Category() models.ActionTrigger {
	return models.EventActivity
}

func (s *UserActivityService) Handle(ctx context.Context, e Event) error {
	utils.LoggerUserActivity(e.UserID, e.EntityID, e.EntityType, string(e.Action))
	activity := models.UserActivity{
		UserID:     e.UserID,
		Action:     string(e.Action),
		EntityID:   e.EntityID,
		EntityType: e.EntityType,
	}
	return s.repo.Log(ctx, activity)
}

func (s *UserActivityService) GetUserActivities(ctx context.Context, id uint) ([]models.UserActivity, error) {
	return s.repo.Get(ctx, id)
}
