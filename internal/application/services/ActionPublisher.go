package services

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"context"

	"go.uber.org/zap"
)

type ActionPublisher struct {
	Subscribers map[models.Actions][]Subscriber
}

func NewActionPublisher() *ActionPublisher {
	return &ActionPublisher{
		Subscribers: make(map[models.Actions][]Subscriber),
	}
}

func (a ActionPublisher) NotifySubscribers(ctx context.Context, e Event) {
	if subscribers, ok := a.Subscribers[e.Action]; ok {
		for _, sub := range subscribers {
			err := sub.Handle(ctx, e)
			if err != nil {
				logger.Error("error while handling subscriber", zap.Any("action", e.Action), zap.Error(err))
			}
			logger.Info("subscriber handled succesfully", zap.Any("action", e.Action))
		}
	}
}

func (a ActionPublisher) AddSubscriber(name models.Actions, s Subscriber) {
	a.Subscribers[name] = append(a.Subscribers[name], s)
}
