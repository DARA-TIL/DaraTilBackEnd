package timeEventUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type FinishTimeEventUC struct {
	timeEventRepo            repo.TimeEventRepo
	timeEventParticipantRepo repo.TimeEventParticipantRepo
	userRepo                 repo.UserRepo
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
	}
	return nil
}
