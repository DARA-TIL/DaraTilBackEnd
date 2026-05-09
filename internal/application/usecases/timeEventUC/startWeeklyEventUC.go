package timeEventUC

import (
	"DaraTilBackendV2/internal/application/services"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"context"
	"fmt"
	"math/rand"
	"time"
)

type StartWeeklyEventUC struct {
	repo     repo.TimeEventRepo
	notifSub services.NotificationSubscriber
}

func NewStartWeeklyEventUC(repo repo.TimeEventRepo, notifSub services.NotificationSubscriber) *StartWeeklyEventUC {
	return &StartWeeklyEventUC{repo: repo, notifSub: notifSub}
}

var weeklyEventActions = []models.Actions{
	models.Lesson_completed,
	models.Folklore_readed,
	models.Region_slang_readed,
	models.Region_tradition_readed,
	models.Word_Learned,
}

func (uc *StartWeeklyEventUC) Execute(ctx context.Context) error {
	loc, err := time.LoadLocation("Asia/Qyzylorda")
	if err != nil {
		return err
	}

	now := time.Now().In(loc)

	weekStart := startOfISOWeek(now)
	weekEnd := weekStart.AddDate(0, 0, 7)
	isWeekly := true
	existingEvents, err := uc.repo.GetAll(ctx, models.TimeEventParams{
		StartDateFrom: &weekStart,
		StartDateTo:   &weekEnd,
		IsWeekly:      &isWeekly,
	})
	if err != nil {
		return err
	}

	if len(existingEvents) > 0 {
		logger.Info("Weekly event already exists")
		return nil
	}
	eventType := getRandomWeeklyAction()

	startDate := weekStart
	endDate := weekEnd.Add(-time.Minute)

	duration := endDate.Sub(startDate)

	event := models.TimeEvent{
		Name:         getWeeklyEventName(eventType),
		Description:  getWeeklyEventDescription(eventType),
		RewardFirst:  300,
		RewardSecond: 200,
		RewardThird:  100,
		EventType:    eventType,
		Duration:     duration,
		IsWeekly:     true,
		StartDate:    startDate,
		EndDate:      endDate,
		Status:       models.Started,
	}

	createdEvent, err := uc.repo.Create(ctx, event)
	if err != nil {
		return err
	}
	eventID := createdEvent.ID

	uc.Notify(ctx, models.Notification{
		Title: fmt.Sprintf(
			"New weekly event: %s",
			createdEvent.Name,
		),
		Message: fmt.Sprintf(
			"The weekly event \"%s\" has started. Join now and compete for rewards.",
			createdEvent.Name,
		),
		Type:     models.NotificationTypeEvent,
		Scope:    models.NotificationScopeGlobal,
		EntityID: &eventID,
		IsActive: true,
	})
	logger.Info("Weekly Event created successfully")
	return nil
}

func getRandomWeeklyAction() models.Actions {
	return weeklyEventActions[rand.Intn(len(weeklyEventActions))]
}
func getWeeklyEventName(action models.Actions) string {
	switch action {
	case models.Lesson_completed:
		return "Weekly Lesson Challenge"
	case models.Folklore_readed:
		return "Weekly Folklore Challenge"
	case models.Region_slang_readed:
		return "Weekly Slang Challenge"
	case models.Region_tradition_readed:
		return "Weekly Tradition Challenge"
	case models.Word_Learned:
		return "Weekly Word Challenge"
	default:
		return "Weekly Challenge"
	}
}
func getWeeklyEventDescription(action models.Actions) string {
	switch action {
	case models.Lesson_completed:
		return "Complete lessons during the week and compete for rewards."
	case models.Folklore_readed:
		return "Read folklore stories during the week and compete for rewards."
	case models.Region_slang_readed:
		return "Read regional slang materials during the week and compete for rewards."
	case models.Region_tradition_readed:
		return "Read regional tradition materials during the week and compete for rewards."
	case models.Word_Learned:
		return "Learn new words during the week and compete for rewards."
	default:
		return "Complete weekly activity and compete for rewards."
	}
}
func startOfISOWeek(t time.Time) time.Time {
	t = t.In(t.Location())

	weekday := int(t.Weekday())
	if weekday == 0 {
		weekday = 7
	}

	year, month, day := t.Date()

	startOfDay := time.Date(
		year,
		month,
		day,
		0,
		0,
		0,
		0,
		t.Location(),
	)

	return startOfDay.AddDate(0, 0, -(weekday - 1))
}
func (uc *StartWeeklyEventUC) Notify(ctx context.Context, notif models.Notification) {
	if uc.notifSub == nil {
		logger.Warn("No notification subscriber")
		return
	}
	uc.notifSub.Handle(ctx, notif)
}

func (uc *StartWeeklyEventUC) AddSubscriber(sub services.NotificationSubscriber) {
	uc.notifSub = sub
}
