package dto

import (
	"DaraTilBackendV2/internal/domain/models"
	"time"
)

type TimeEvent struct {
	ID           uint                   `json:"id"`
	Name         string                 `json:"name"`
	Description  string                 `json:"description"`
	RewardFirst  int                    `json:"rewardFirst"`
	RewardSecond int                    `json:"rewardSecond"`
	RewardThird  int                    `json:"rewardThird"`
	EventType    models.Actions         `json:"eventType"`
	Duration     uint                   `json:"duration"`
	StartDate    time.Time              `json:"startDate"`
	EndDate      time.Time              `json:"endDate"`
	Participants []TimeEventParticipant `json:"participants"`
	Status       models.TimeEventStatus `json:"status"`
}

type CreateTimeEventRequest struct {
	Name         string                  `json:"name"`
	Description  *string                 `json:"description,omitempty"`
	RewardFirst  *int                    `json:"rewardFirst,omitempty"`
	RewardSecond *int                    `json:"rewardSecond,omitempty"`
	RewardThird  *int                    `json:"rewardThird,omitempty"`
	EventType    models.Actions          `json:"eventType"`
	Duration     uint                    `json:"duration"`
	StartDate    time.Time               `json:"startDate"`
	EndDate      time.Time               `json:"endDate"`
	Status       *models.TimeEventStatus `json:"status"`
}

type UpdateTimeEventRequest struct {
	ID           uint                    `json:"id"`
	Name         *string                 `json:"name,omitempty"`
	Description  *string                 `json:"description,omitempty"`
	RewardFirst  *int                    `json:"rewardFirst,omitempty"`
	RewardSecond *int                    `json:"rewardSecond,omitempty"`
	RewardThird  *int                    `json:"rewardThird,omitempty"`
	EventType    *models.Actions         `json:"eventType,omitempty"`
	Duration     *int                    `json:"duration,omitempty"`
	StartDate    *time.Time              `json:"startDate,omitempty"`
	EndDate      *time.Time              `json:"endDate,omitempty"`
	Status       *models.TimeEventStatus `json:"status,omitempty"`
}

type TimeEventParticipant struct {
	ID          uint `json:"id"`
	UserID      uint `json:"userId"`
	TimeEventID uint `json:"timeEventId"`
	Count       int  `json:"count"`
	IsActive    bool `json:"isActive"`
	Place       int  `json:"place"`
	User        User `json:"user"`
}
type CreateTimeEventParticipantRequest struct {
	UserID      uint  `json:"userId"`
	TimeEventID uint  `json:"timeEventId"`
	Count       *int  `json:"count,omitempty"`
	IsActive    *bool `json:"isActive,omitempty"`
	Place       *int  `json:"place,omitempty"`
}
type UpdateTimeEventParticipantRequest struct {
	ID          uint  `json:"id"`
	UserID      *uint `json:"userId,omitempty"`
	TimeEventID *uint `json:"timeEventId,omitempty"`
	Count       *int  `json:"count,omitempty"`
	IsActive    *bool `json:"isActive,omitempty"`
	Place       *int  `json:"place,omitempty"`
}
type GetTimeEventsQuery struct {
	EventType     *string    `form:"eventType"`
	Status        *string    `form:"status"`
	StartDateFrom *time.Time `form:"startDateFrom" time_format:"2006-01-02T15:04:05Z07:00"`
	StartDateTo   *time.Time `form:"startDateTo" time_format:"2006-01-02T15:04:05Z07:00"`
	EndDateFrom   *time.Time `form:"endDateFrom" time_format:"2006-01-02T15:04:05Z07:00"`
	EndDateTo     *time.Time `form:"endDateTo" time_format:"2006-01-02T15:04:05Z07:00"`
}
