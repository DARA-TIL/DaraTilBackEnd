package services

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"context"

	"go.uber.org/zap"
)

type ActionPublisher struct {
	Subscribers     map[models.Actions][]Subscriber
	ActionRulesRepo repo.ActionRuleRepo
}

func NewActionPublisher(ar repo.ActionRuleRepo) *ActionPublisher {
	return &ActionPublisher{
		Subscribers:     make(map[models.Actions][]Subscriber),
		ActionRulesRepo: ar,
	}
}

func (a *ActionPublisher) Publish(ctx context.Context, e Event) {
	rules, err := a.ActionRulesRepo.GetByAction(ctx, e.Action)
	if err != nil {
		logger.Error("Error getting action rules", zap.Error(err))
		return
	}
	if subscribers, ok := a.Subscribers[e.Action]; ok {
		if rules.Rules == nil {
			logger.Warn("no rules found for action", zap.Any("action", e.Action))
			return
		}
		for _, sub := range subscribers {
			if !rules.Rules[sub.Category()] {
				continue
			}
			err := sub.Handle(ctx, e)
			if err != nil {
				logger.Error("error while handling subscriber", zap.Any("action", e.Action), zap.Any("category", sub.Category()), zap.Error(err))
			}
			logger.Info("subscriber handled succesfully", zap.Any("action", e.Action), zap.Any("category", sub.Category()))
		}
	}
}

func (a *ActionPublisher) AddSubscriber(s Subscriber) {
	a.Subscribers[models.Lesson_completed] = append(a.Subscribers[models.Lesson_completed], s)
	a.Subscribers[models.Folklore_liked] = append(a.Subscribers[models.Folklore_liked], s)
	a.Subscribers[models.Folklore_disliked] = append(a.Subscribers[models.Folklore_disliked], s)
	a.Subscribers[models.Folklore_readed] = append(a.Subscribers[models.Folklore_readed], s)
	a.Subscribers[models.Level_upgraded] = append(a.Subscribers[models.Level_upgraded], s)
	a.Subscribers[models.Region_slang_readed] = append(a.Subscribers[models.Region_slang_readed], s)
	a.Subscribers[models.Region_tradition_readed] = append(a.Subscribers[models.Region_tradition_readed], s)
}
