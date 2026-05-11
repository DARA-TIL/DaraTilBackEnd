package timeEventUC

import (
	"DaraTilBackendV2/internal/application/services"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
	"fmt"
)

type FinishTimeEventUC struct {
	timeEventRepo            repo.TimeEventRepo
	timeEventParticipantRepo repo.TimeEventParticipantRepo
	userRepo                 repo.UserRepo
	notifSub                 services.NotificationSubscriber
}

func NewFinishTimeEventUC(
	timeEventRepo repo.TimeEventRepo,
	timeEventParticipantRepo repo.TimeEventParticipantRepo,
	userRepo repo.UserRepo,
) *FinishTimeEventUC {
	return &FinishTimeEventUC{
		timeEventRepo:            timeEventRepo,
		timeEventParticipantRepo: timeEventParticipantRepo,
		userRepo:                 userRepo,
	}
}

func (uc *FinishTimeEventUC) Execute(ctx context.Context, eventID uint) error {
	err := uc.timeEventRepo.ChangeEventStatus(ctx, eventID, models.Ended)
	if err != nil {
		return err
	}
	err = uc.timeEventParticipantRepo.UpdatePlaces(ctx, eventID)
	if err != nil {
		return err
	}
	event, err := uc.timeEventRepo.GetByID(ctx, eventID)
	if err != nil {
		return err
	}
	winners, err := uc.timeEventParticipantRepo.GetEventParticipants(ctx, eventID, 3)
	if err != nil {
		return err
	}
	rewardsMap := make(map[int]int)
	if event.RewardFirst != 0 {
		rewardsMap[1] = event.RewardFirst
		if event.RewardSecond != 0 {
			rewardsMap[2] = event.RewardSecond
			if event.RewardThird != 0 {
				rewardsMap[3] = event.RewardThird
			}
		}
	}
	for _, winner := range winners {
		reward, ok := rewardsMap[winner.Place]
		if !ok {
			continue
		}
		lvlRet := uc.userRepo.LvlUp(ctx, winner.UserID, reward)
		if lvlRet.Err != nil {
			return lvlRet.Err
		}
		eventIDCopy := event.ID
		userID := winner.UserID

		title := fmt.Sprintf("Event reward: %s", event.Name)

		message := fmt.Sprintf(
			"You finished in place #%d in \"%s\" and received %d XP.",
			winner.Place,
			event.Name,
			reward,
		)

		uc.Notify(ctx, models.Notification{
			Title:    title,
			Message:  message,
			Type:     models.NotificationTypeReward,
			Scope:    models.NotificationScopeUser,
			UserID:   &userID,
			EntityID: &eventIDCopy,
			IsActive: true,
		})
	}
	return nil
}
func (uc *FinishTimeEventUC) Notify(ctx context.Context, notif models.Notification) {
	uc.notifSub.Handle(ctx, notif)
}

func (uc *FinishTimeEventUC) AddSubscriber(sub services.NotificationSubscriber) {
	uc.notifSub = sub
}
