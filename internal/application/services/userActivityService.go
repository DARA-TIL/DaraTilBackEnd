package services

import (
	"DaraTilBackendV2/internal/application/utils"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type UserActivityService struct {
	repo          repo.UserActivityRepo
	streakService *StreakService
}

func NewUserActivityService(repo repo.UserActivityRepo, streakService *StreakService) *UserActivityService {
	return &UserActivityService{repo: repo, streakService: streakService}
}

func (s *UserActivityService) LogActivityWithoutStreak(ctx context.Context, action models.Actions, entityType string, userID, entityID uint) error {
	utils.LoggerUserActivity(userID, entityID, entityType, string(action))
	activity := models.UserActivity{
		UserID:     userID,
		Action:     string(action),
		EntityID:   entityID,
		EntityType: entityType,
	}
	return s.repo.Log(ctx, activity)
}

func (s *UserActivityService) LogActivity(ctx context.Context, action models.Actions, entityType string, userID, entityID uint) (StreakUpdateResult, error) {
	res, err := s.streakService.UpdateOnActivity(ctx, userID)
	if err != nil {
		return res, err
	}
	utils.LoggerUserActivity(userID, entityID, entityType, string(action))

	activity := models.UserActivity{
		UserID:     userID,
		Action:     string(action),
		EntityID:   entityID,
		EntityType: entityType,
	}
	return res, s.repo.Log(ctx, activity)
}
func (s *UserActivityService) GetUserActivities(ctx context.Context, id uint) ([]models.UserActivity, error) {
	return s.repo.Get(ctx, id)
}
