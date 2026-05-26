package models

import "time"

type DailyActionUsage struct {
	ID uint

	UserID uint

	Action string

	UsageDate time.Time
	Count     int

	CreatedAt time.Time
	UpdatedAt time.Time
}
