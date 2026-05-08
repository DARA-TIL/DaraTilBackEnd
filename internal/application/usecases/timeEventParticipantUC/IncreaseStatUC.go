package timeEventParticipantUC

import (
	"DaraTilBackendV2/internal/application/services"
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"context"
	"errors"
)

type IncreaseTEPStatUC struct { //TEP - Time Event Participant
	TEPRepo       repo.TimeEventParticipantRepo
	TimeEventRepo repo.TimeEventRepo
}

func NewIncreaseTEPStatUC(tepRepo repo.TimeEventParticipantRepo, timeEventRepo repo.TimeEventRepo) *IncreaseTEPStatUC {
	return &IncreaseTEPStatUC{TEPRepo: tepRepo, TimeEventRepo: timeEventRepo}
}

func (uc *IncreaseTEPStatUC) Category() models.ActionTrigger {
	return models.TimeEventTrigger
}

func (uc *IncreaseTEPStatUC) Handle(ctx context.Context, e services.Event) error {
	started := models.Started
	events, err := uc.TimeEventRepo.GetAll(ctx, models.TimeEventParams{
		EventType: &e.Action,
		Status:    &started,
	})
	if err != nil {
		return err
	}
	if len(events) == 0 {
		logger.Info("No events found")
		return nil
	}
	for _, event := range events {
		var p *models.TimeEventParticipant
		p, err = uc.TEPRepo.GetEventParticipantByUserAndEventID(ctx, e.UserID, event.ID)
		if err != nil {
			if errors.Is(err, errs.ErrNotFound) {
				var createError error
				p, createError = uc.TEPRepo.Create(ctx, models.TimeEventParticipant{
					UserID:      e.UserID,
					TimeEventID: event.ID,
				})
				if createError != nil {
					return createError
				}
			} else {
				return err
			}
		}
		if !p.IsActive {
			logger.Info("Event participant is not active")
			return nil
		}
		err = uc.TEPRepo.IncreaseStat(ctx, p.ID)
		if err != nil {
			return err
		}
		err = uc.TEPRepo.UpdatePlaces(ctx, event.ID)
		if err != nil {
			return err
		}
	}
	return nil
}
