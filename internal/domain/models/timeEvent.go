package models

import "time"

type TimeEvent struct {
	ID           uint
	Name         string
	Description  string
	RewardFirst  int
	RewardSecond int
	RewardThird  int
	EventType    Actions
	Duration     time.Duration
	StartDate    time.Time
	EndDate      time.Time
	IsWeekly     bool
	Participants []TimeEventParticipant
	Status       TimeEventStatus
}

type TimeEventParams struct {
	EventType     *Actions
	Status        *TimeEventStatus
	StartDateFrom *time.Time
	StartDateTo   *time.Time
	EndDateFrom   *time.Time
	EndDateTo     *time.Time
	IsWeekly      *bool
}

type TimeEventParticipant struct {
	ID          uint
	UserID      uint
	TimeEventID uint
	Count       int
	IsActive    bool
	Place       int

	User User
}
