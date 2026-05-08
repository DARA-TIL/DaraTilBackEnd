package dtoMappers

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/presentation/dto"
	"time"
)

func TimeEventToDto(event models.TimeEvent) dto.TimeEvent {
	return dto.TimeEvent{
		ID:           event.ID,
		Name:         event.Name,
		Description:  event.Description,
		RewardFirst:  event.RewardFirst,
		RewardSecond: event.RewardSecond,
		RewardThird:  event.RewardThird,
		EventType:    event.EventType,

		Duration: uint(event.Duration / time.Hour),

		StartDate:    event.StartDate,
		EndDate:      event.EndDate,
		Participants: TimeEventParticipantsToDto(event.Participants),
		Status:       event.Status,
	}
}

func TimeEventsToDto(events []models.TimeEvent) []dto.TimeEvent {
	result := make([]dto.TimeEvent, 0, len(events))

	for _, event := range events {
		result = append(result, TimeEventToDto(event))
	}

	return result
}

func TimeEventFromCreateRequest(req dto.CreateTimeEventRequest) models.TimeEvent {
	event := models.TimeEvent{
		Name:      req.Name,
		EventType: req.EventType,

		Duration: time.Duration(req.Duration) * time.Hour,

		StartDate: req.StartDate,
		EndDate:   req.EndDate,
	}

	if req.Description != nil {
		event.Description = *req.Description
	}

	if req.RewardFirst != nil {
		event.RewardFirst = *req.RewardFirst
	}

	if req.RewardSecond != nil {
		event.RewardSecond = *req.RewardSecond
	}

	if req.RewardThird != nil {
		event.RewardThird = *req.RewardThird
	}

	if req.Status != nil {
		event.Status = *req.Status
	}

	return event
}

func TimeEventFromUpdateRequest(req dto.UpdateTimeEventRequest) models.TimeEvent {
	event := models.TimeEvent{
		ID: req.ID,
	}
	if req.Name != nil {
		event.Name = *req.Name
	}
	if req.Description != nil {
		event.Description = *req.Description
	}

	if req.RewardFirst != nil {
		event.RewardFirst = *req.RewardFirst
	}

	if req.RewardSecond != nil {
		event.RewardSecond = *req.RewardSecond
	}

	if req.RewardThird != nil {
		event.RewardThird = *req.RewardThird
	}

	if req.EventType != nil {
		event.EventType = *req.EventType
	}

	if req.Duration != nil {
		// frontend hours -> backend time.Duration
		event.Duration = time.Duration(*req.Duration) * time.Hour
	}

	if req.StartDate != nil {
		event.StartDate = *req.StartDate
	}

	if req.EndDate != nil {
		event.EndDate = *req.EndDate
	}

	if req.Status != nil {
		event.Status = *req.Status
	}

	return event
}

func TimeEventParticipantToDto(participant models.TimeEventParticipant) dto.TimeEventParticipant {
	return dto.TimeEventParticipant{
		ID:          participant.ID,
		UserID:      participant.UserID,
		TimeEventID: participant.TimeEventID,
		Count:       participant.Count,
		IsActive:    participant.IsActive,
		Place:       participant.Place,
		User:        UserToDto(participant.User),
	}
}

func TimeEventParticipantsToDto(participants []models.TimeEventParticipant) []dto.TimeEventParticipant {
	result := make([]dto.TimeEventParticipant, 0, len(participants))

	for _, participant := range participants {
		result = append(result, TimeEventParticipantToDto(participant))
	}

	return result
}
func TimeEventParticipantFromCreateRequest(req dto.CreateTimeEventParticipantRequest) models.TimeEventParticipant {
	participant := models.TimeEventParticipant{
		UserID:      req.UserID,
		TimeEventID: req.TimeEventID,
	}

	if req.Count != nil {
		participant.Count = *req.Count
	}

	if req.IsActive != nil {
		participant.IsActive = *req.IsActive
	} else {
		participant.IsActive = true
	}

	if req.Place != nil {
		participant.Place = *req.Place
	}

	return participant
}

func TimeEventParticipantFromUpdateRequest(req dto.UpdateTimeEventParticipantRequest) models.TimeEventParticipant {
	participant := models.TimeEventParticipant{
		ID: req.ID,
	}

	if req.UserID != nil {
		participant.UserID = *req.UserID
	}

	if req.TimeEventID != nil {
		participant.TimeEventID = *req.TimeEventID
	}

	if req.Count != nil {
		participant.Count = *req.Count
	}

	if req.IsActive != nil {
		participant.IsActive = *req.IsActive
	}

	if req.Place != nil {
		participant.Place = *req.Place
	}

	return participant
}

func TimeEventParamsFromQuery(req dto.GetTimeEventsQuery) (models.TimeEventParams, error) {
	params := models.TimeEventParams{}

	if req.EventType != nil && *req.EventType != "" {
		eventType := models.Actions(*req.EventType)
		params.EventType = &eventType
	}

	if req.Status != nil && *req.Status != "" {
		status := models.TimeEventStatus(*req.Status)
		params.Status = &status
	}

	if req.StartDateFrom != nil {
		params.StartDateFrom = req.StartDateFrom
	}

	if req.StartDateTo != nil {
		params.StartDateTo = req.StartDateTo
	}

	if req.EndDateFrom != nil {
		params.EndDateFrom = req.EndDateFrom
	}

	if req.EndDateTo != nil {
		params.EndDateTo = req.EndDateTo
	}

	return params, nil
}
