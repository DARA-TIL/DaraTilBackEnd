package services

import (
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
func (s *UserActivityService) LogActivity(ctx context.Context, action models.Actions, entityType string, userID, entityID uint) error {
	activity := models.UserActivity{
		UserID:     userID,
		Action:     string(action),
		EntityID:   entityID,
		EntityType: entityType,
	}
	return s.repo.Log(ctx, activity)
}
func (s *UserActivityService) GetUserActivities(ctx context.Context, id uint) ([]models.UserActivity, error) {
	return s.repo.Get(ctx, id)
}
