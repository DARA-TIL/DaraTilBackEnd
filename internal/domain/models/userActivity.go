package models

import "time"

type Actions string

const (
	Lesson_completed  Actions = "lesson_completed"
	Folklore_liked    Actions = "folklore_liked"
	Folklore_disliked Actions = "folklore_disliked"
)

type UserActivity struct {
	ID         uint
	Time       time.Time
	Action     string
	UserID     uint
	EntityType string
	EntityID   uint
}
