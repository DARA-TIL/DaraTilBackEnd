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
	Publish(ctx context.Context, e Event)
	AddSubscribers(s Subscriber, actions ...models.Actions)
}

type Event struct {
	Action     models.Actions
	UserID     uint
	EntityID   uint
	EntityType models.EventEntityType
}
