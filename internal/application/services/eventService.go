package services

import (
	"DaraTilBackendV2/internal/domain/models"
	"context"
)

type Subscriber interface {
	Category() models.ActionTrigger
	Handle(ctx context.Context, e Event) error
}

type Publisher interface {
	NotifySubscribers(ctx context.Context, e Event)
	AddSubscriber(s Subscriber)
}

type Event struct {
	Action     models.Actions
	UserID     uint
	EntityID   uint
	EntityType models.EventEntityType
}
