package models

import "time"

type Actions string

const (
	Lesson_completed        Actions = "lesson_completed"
	Folklore_liked          Actions = "folklore_liked"
	Folklore_disliked       Actions = "folklore_disliked"
	Folklore_readed         Actions = "folklore_readed"
	Level_upgraded          Actions = "level_upgraded"
	Region_slang_opened     Actions = "region_slang_opened"
	Region_tradition_opened Actions = "region_tradition_opened"
)

type UserActivity struct {
	ID         uint
	Time       time.Time
	Action     string
	UserID     uint
	EntityType string
	EntityID   uint
}
