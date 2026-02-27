package models

import "time"

type Streak struct {
	ID            uint
	UserID        uint
	CurrentStreak int
	LongestStreak int
	LastActivity  time.Time
}
