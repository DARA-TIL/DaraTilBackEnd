package services

import (
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"DaraTilBackendV2/internal/infrastructure/utils"
	"context"
	"errors"
	"fmt"
	"time"

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
	repo     repo.StreakRepo
	NotifSub NotificationSubscriber
}

func NewStreakService(repo repo.StreakRepo) *StreakService {
	return &StreakService{repo: repo}
}

func (s *StreakService) Category() models.ActionTrigger {
	return models.EventStreak
}

func (s *StreakService) Handle(ctx context.Context, e Event) error {
	logger.Info("Checking User Streak", zap.Uint("user_id", e.UserID))
	today := utils.TodayInLocation()
	streak, err := s.repo.GetByUserID(ctx, e.UserID)
	if errors.Is(err, errs.ErrNotFound) {
		logger.Info("User Streak not found, creating new one", zap.Uint("user_id", e.UserID))
		newStreak := models.Streak{
			UserID:        e.UserID,
			CurrentStreak: 1,
			LongestStreak: 1,
			LastActivity:  today,
		}
		err = s.repo.Create(ctx, newStreak)
		if err != nil {
			logger.Error("Failed to create new Streak", zap.Error(err))
			return err
		}
		notification := buildStreakNotification(e.UserID, 1)

		s.Notify(ctx, notification)
		return nil
	}
	if err != nil {
		logger.Error("Failed to get Streak", zap.Error(err))
		return err
	}
	if sameDay(streak.LastActivity, today) {
		return nil
	} else if sameDay(streak.LastActivity.AddDate(0, 0, 1), today) {
		logger.Info("Incrementing user streak", zap.Uint("user_id", e.UserID))
		err = s.repo.Increment(ctx, e.UserID)
		if err != nil {
			logger.Error("Failed to increment user streak", zap.Error(err))
			return err
		}
		str, err := s.repo.GetByUserID(ctx, e.UserID)
		if err != nil {
			logger.Error("Failed to get user streak", zap.Error(err))
			return nil
		}
		notification := buildStreakNotification(e.UserID, str.CurrentStreak)

		s.Notify(ctx, notification)
		return nil
	}
	logger.Info("Staring new user streak", zap.Uint("user_id", e.UserID))
	err = s.repo.Start(ctx, e.UserID)
	if err != nil {
		logger.Error("Failed to start user streak", zap.Error(err))
		return err
	}
	notification := buildStreakNotification(e.UserID, 1)

	s.Notify(ctx, notification)
	return nil
}

func (s *StreakService) CheckStreaks(ctx context.Context) error {
	resetStreaks, err := s.repo.DailyStreakCheck(ctx)
	if err != nil {
		return err
	}
	for _, resetStreak := range resetStreaks {
		notif := models.Notification{
			Title:    "Streak Reset",
			Message:  "Your streak has been reset. Start again today to build a new streak.",
			Type:     models.NotificationTypeStreak,
			Scope:    models.NotificationScopeUser,
			UserID:   &resetStreak.UserID,
			IsActive: true,
		}
		s.Notify(ctx, notif)
	}
	logger.Info("Finished checking user streaks", zap.Int("reset_streaks_count", len(resetStreaks)))
	return nil
}
func (s *StreakService) Notify(ctx context.Context, notif models.Notification) {
	if s.NotifSub == nil {
		logger.Warn("notification subscriber is not set")
		return
	}

	s.NotifSub.Handle(ctx, notif)
}
func (s *StreakService) AddSubscriber(sub NotificationSubscriber) {
	s.NotifSub = sub
}
func buildStreakNotification(userID uint, streak int) models.Notification {
	title := "Streak updated"
	message := fmt.Sprintf("Your current streak is %d day(s). Keep going!", streak)

	if streak == 0 {
		title = "Streak reset"
		message = "Your streak has been reset. Start again today to build a new streak."
	}

	return models.Notification{
		Title:    title,
		Message:  message,
		Type:     models.NotificationTypeStreak,
		Scope:    models.NotificationScopeUser,
		UserID:   &userID,
		IsActive: true,
	}
}
func sameDay(a, b time.Time) bool {
	ay, am, ad := a.Date()
	by, bm, bd := b.Date()
	return ay == by && am == bm && ad == bd
}
