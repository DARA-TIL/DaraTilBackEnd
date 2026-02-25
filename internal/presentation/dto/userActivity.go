package dto

import "time"

type UserActivityDTO struct {
	ID         uint      `json:"id"`
	Time       time.Time `json:"time"`
	Action     string    `json:"action"`
	UserID     uint      `json:"userID"`
	EntityType string    `json:"entityType"`
	EntityID   uint      `json:"entityID"`
}
