package timeEventUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"context"
	"time"

	"go.uber.org/zap"
)

type UpdateDueTimeEventsUC struct {
	repo              repo.TimeEventRepo
	finishTimeEventUC *FinishTimeEventUC
}

func NewUpdateDueTimeEventsUC(repo repo.TimeEventRepo, finishTimeEventUC *FinishTimeEventUC) *UpdateDueTimeEventsUC {
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
	err = uc.repo.StartDueEvents(ctx)
	if err != nil {
		return err
	}
	return nil
}
