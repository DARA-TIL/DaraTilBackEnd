package services

import (
	"DaraTilBackendV2/internal/domain/models"
	"context"
)

type Subscriber interface {
	Handle(ctx context.Context, e Event) error
}

type Publisher interface {
	NotifySubscribers(ctx context.Context, e Event)
	AddSubscriber(name models.Actions, s Subscriber)
}
type Event struct {
	Action models.Actions
	UserID uint
}
