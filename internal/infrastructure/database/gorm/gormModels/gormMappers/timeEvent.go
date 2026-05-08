package gormMappers

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
)

func TimeEventToGormModel(event models.TimeEvent) gormModels.TimeEvent {
	return gormModels.TimeEvent{
		Name:         event.Name,
		Description:  event.Description,
		RewardFirst:  event.RewardFirst,
		RewardSecond: event.RewardSecond,
		RewardThird:  event.RewardThird,
		EventType:    string(event.EventType),
		IsWeekly:     event.IsWeekly,
		Duration:     event.Duration,
		StartDate:    event.StartDate,
		EndDate:      event.EndDate,
		Status:       event.Status,
	}
}

func GormTimeEventToDomainModel(event gormModels.TimeEvent) models.TimeEvent {
	return models.TimeEvent{
		ID:           event.ID,
		Name:         event.Name,
		Description:  event.Description,
		RewardFirst:  event.RewardFirst,
		RewardSecond: event.RewardSecond,
		RewardThird:  event.RewardThird,
		EventType:    models.Actions(event.EventType),
		Duration:     event.Duration,
		StartDate:    event.StartDate,
		EndDate:      event.EndDate,
		Participants: GormTimeEventParticipantsToDomainModel(event.Participants),
		Status:       event.Status,
	}
}

func TimeEventsToGormModel(events []models.TimeEvent) []gormModels.TimeEvent {
	var gormEvents []gormModels.TimeEvent

	for _, event := range events {
		gormEvents = append(gormEvents, TimeEventToGormModel(event))
	}

	return gormEvents
}

func GormTimeEventsToDomainModel(events []gormModels.TimeEvent) []models.TimeEvent {
	var domainEvents []models.TimeEvent

	for _, event := range events {
		domainEvents = append(domainEvents, GormTimeEventToDomainModel(event))
	}

	return domainEvents
}

func TimeEventParticipantToGormModel(participant models.TimeEventParticipant) gormModels.TimeEventParticipant {
	return gormModels.TimeEventParticipant{
		ID:          participant.ID,
		UserID:      participant.UserID,
		TimeEventID: participant.TimeEventID,
		Count:       participant.Count,
		IsActive:    participant.IsActive,
		Place:       participant.Place,
		User:        UserToGormModel(participant.User),
	}
}

func GormTimeEventParticipantToDomainModel(participant gormModels.TimeEventParticipant) models.TimeEventParticipant {
	return models.TimeEventParticipant{
		ID:          participant.ID,
		UserID:      participant.UserID,
		TimeEventID: participant.TimeEventID,
		Count:       participant.Count,
		IsActive:    participant.IsActive,
		Place:       participant.Place,
		User:        GormUserToDomain(participant.User),
	}
}

func TimeEventParticipantsToGormModel(participants []models.TimeEventParticipant) []gormModels.TimeEventParticipant {
	var gormParticipants []gormModels.TimeEventParticipant

	for _, participant := range participants {
		gormParticipants = append(gormParticipants, TimeEventParticipantToGormModel(participant))
	}

	return gormParticipants
}

func GormTimeEventParticipantsToDomainModel(participants []gormModels.TimeEventParticipant) []models.TimeEventParticipant {
	var domainParticipants []models.TimeEventParticipant

	for _, participant := range participants {
		domainParticipants = append(domainParticipants, GormTimeEventParticipantToDomainModel(participant))
	}

	return domainParticipants
}
