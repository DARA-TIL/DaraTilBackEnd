package models

import "time"

type TimeEvent struct {
	ID           uint
	Name         string
	Description  string
	RewardFirst  uint
	RewardSecond uint
	RewardThird  uint
	EventType    string
	Duration     time.Duration
	StartDate    time.Time
	EndDate      time.Time
	Users        []User
	IsActive     bool
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
