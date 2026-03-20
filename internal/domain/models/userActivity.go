package models

import "time"

type UserActivity struct {
	ID         uint
	Time       time.Time
	Action     string
	UserID     uint
	EntityType EventEntityType
	EntityID   uint
}
