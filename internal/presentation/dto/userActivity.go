package dto

import (
	"DaraTilBackendV2/internal/domain/models"
	"time"
)

type UserActivityDTO struct {
	ID         uint                   `json:"id"`
	Time       time.Time              `json:"time"`
	Action     string                 `json:"action"`
	UserID     uint                   `json:"userID"`
	EntityType models.EventEntityType `json:"entityType"`
	EntityID   uint                   `json:"entityID"`
}
