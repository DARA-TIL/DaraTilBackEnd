package timeEventUC

import (
	"DaraTilBackendV2/internal/application/services"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
)

type UpdateDueTimeEventsUC struct {
	repo              repo.TimeEventRepo
	finishTimeEventUC *FinishTimeEventUC
	notifSub          services.NotificationSubscriber
}

func NewUpdateDueTimeEventsUC(repo repo.TimeEventRepo,
	finishTimeEventUC *FinishTimeEventUC,
) *UpdateDueTimeEventsUC {
	return &UpdateDueTimeEventsUC{repo: repo, finishTimeEventUC: finishTimeEventUC}
}

func (uc *UpdateDueTimeEventsUC) Execute(ctx context.Context) error {
	now := time.Now()
	started := models.Started
	endedEvents, err := uc.repo.GetAll(ctx, models.TimeEventParams{
		Status:    &started,
		EndDateTo: &now,
	})
	if err != nil {
		return err
	}
	for _, event := range endedEvents {
		err := uc.finishTimeEventUC.Execute(ctx, event.ID)
		if err != nil {
			logger.Error(
				"failed to finish time event",
				zap.Uint("eventID", event.ID),
				zap.Error(err),
			)
			continue
		}
		logger.Info("finished time event", zap.Uint("eventID", event.ID))
	}
	startedEvents, err := uc.repo.StartDueEvents(ctx)
	if err != nil {
		return err
	}
	if len(startedEvents) != 0 {
		for _, event := range startedEvents {
			eventMessage := fmt.Sprintf(
				"The event \"%s\" has started. Join now and compete for rewards.",
				event.Name,
			)
			notification := models.Notification{
				Title:    "New Event Started!",
				Message:  eventMessage,
				Type:     models.NotificationTypeEvent,
				Scope:    models.NotificationScopeGlobal,
				EntityID: &event.ID,
			}
			uc.Notify(ctx, notification)
		}
	}
	return nil
}
func (uc *UpdateDueTimeEventsUC) Notify(ctx context.Context, notif models.Notification) {
	uc.notifSub.Handle(ctx, notif)
}

func (uc *UpdateDueTimeEventsUC) AddSubscriber(sub services.NotificationSubscriber) {
	uc.notifSub = sub
}
