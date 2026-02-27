package services

import (
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"DaraTilBackendV2/internal/infrastructure/utils"
	"context"
	"errors"

	"go.uber.org/zap"
)

type StreakUpdateResult int

const (
	NoChange StreakUpdateResult = iota
	Incremented
	Reset
	Created
	NewStart
)

func StreakResultToString(streakResult StreakUpdateResult) string {
	switch streakResult {
	case NoChange:
		return "NoChange"
	case Incremented:
		return "Incremented"
	case Reset:
		return "Reset"
	case Created:
		return "Created"
	case NewStart:
		return "NewStart"
	}
	return "NoChange"
}

type StreakService struct {
	repo repo.StreakRepo
}

func NewStreakService(repo repo.StreakRepo) *StreakService {
	return &StreakService{repo: repo}
}
func (s *StreakService) UpdateOnActivity(ctx context.Context, userID uint) (StreakUpdateResult, error) {
	logger.Info("Checking User Streak", zap.Uint("user_id", userID))
	today := utils.TodayUTC()
	streak, err := s.repo.GetByUserID(ctx, userID)
	if errors.Is(err, errs.ErrNotFound) {
		logger.Info("User Streak not found, creating new one", zap.Uint("user_id", userID))
		newStreak := models.Streak{
			UserID:        userID,
			CurrentStreak: 1,
			LongestStreak: 1,
			LastActivity:  today,
		}
		err = s.repo.Create(ctx, newStreak)
		if err != nil {
			logger.Error("Failed to create new Streak", zap.Error(err))
			return NoChange, err
		}
		return Created, nil
	}
	if err != nil {
		logger.Error("Failed to get Streak", zap.Error(err))
		return NoChange, err
	}
	if streak.LastActivity.Equal(today) {
		return NoChange, nil
	} else if today.Equal(streak.LastActivity.AddDate(0, 0, 1)) {
		logger.Info("Incrementing user streak", zap.Uint("user_id", userID))
		err = s.repo.Increment(ctx, userID)
		if err != nil {
			logger.Error("Failed to increment user streak", zap.Error(err))
			return NoChange, err
		}
		return Incremented, nil
	}
	logger.Info("Staring new user streak", zap.Uint("user_id", userID))
	err = s.repo.Start(ctx, userID)
	if err != nil {
		logger.Error("Failed to start user streak", zap.Error(err))
		return NoChange, err
	}
	return NewStart, nil
}
func (s *StreakService) CheckStreak(ctx context.Context, userID uint) (StreakUpdateResult, error) {
	streak, err := s.repo.GetByUserID(ctx, userID)
	if errors.Is(err, errs.ErrNotFound) {
		newStreak := models.Streak{
			UserID: userID,
		}
		err = s.repo.Create(ctx, newStreak)
		if err != nil {
			return NoChange, err
		}
		return Created, nil
	}
	if err != nil {
		return NoChange, err
	}
	today := utils.TodayUTC()
	if !streak.LastActivity.Equal(today) && !today.Equal(streak.LastActivity.AddDate(0, 0, 1)) && streak.CurrentStreak != 0 {
		err := s.repo.Reset(ctx, userID)
		if err != nil {
			return NoChange, err
		}
		return Reset, nil
	}
	return NoChange, nil
}
