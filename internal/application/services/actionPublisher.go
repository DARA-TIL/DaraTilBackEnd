package services

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"context"

	"go.uber.org/zap"
)

type ActionPublisher struct {
	Subscribers     map[models.Actions]map[models.ActionTrigger]Subscriber
	ActionRulesRepo repo.ActionRuleRepo
}

func NewActionPublisher(ar repo.ActionRuleRepo) *ActionPublisher {
	return &ActionPublisher{
		Subscribers:     make(map[models.Actions]map[models.ActionTrigger]Subscriber),
		ActionRulesRepo: ar,
	}
}

func (a *ActionPublisher) Publish(ctx context.Context, e Event) {
	actionSubs, ok := a.Subscribers[e.Action]
	if !ok {
		return
	}
	if isStatsAction(e.Action) {
		statsSub, ok := actionSubs[models.StatsImprovement]
		if ok {
			err := statsSub.Handle(ctx, e)
			if err != nil {
				logger.Error("error while handling subscriber", zap.Any("action", e.Action), zap.Any("category", statsSub.Category()), zap.Error(err))
			} else {
				logger.Info("subscriber handled successfully", zap.Any("action", e.Action), zap.Any("category", statsSub.Category()))
			}
		}
	}
	rules, err := a.ActionRulesRepo.GetByAction(ctx, e.Action)
	if err != nil {
		logger.Error("Error getting action rules", zap.Error(err))
		return
	}
	if rules.Rules == nil {
		logger.Warn("no rules found for action", zap.Any("action", e.Action))
		return
	}
	for tr, sub := range actionSubs {
		if tr == models.StatsImprovement {
			continue
		}
		if !rules.Rules[tr] {
			continue
		}
		a.handleSubscriber(ctx, e, tr, sub)
	}
}
func (a *ActionPublisher) handleSubscriber(ctx context.Context, e Event, trigger models.ActionTrigger, sub Subscriber) {
	err := sub.Handle(ctx, e)
	if err != nil {
		logger.Error(
			"error while handling subscriber",
			zap.Any("action", e.Action),
			zap.Any("category", trigger),
			zap.Error(err),
		)
		return
	}

	logger.Info(
		"subscriber handled successfully",
		zap.Any("action", e.Action),
		zap.Any("category", trigger),
	)
}
func isStatsAction(action models.Actions) bool {
	return action == models.Word_Learned
}
func (a *ActionPublisher) AddSubscribers(s Subscriber, actions ...models.Actions) {
	if len(actions) == 0 {
		return
	}
	for _, action := range actions {
		if a.Subscribers[action] == nil {
			a.Subscribers[action] = make(map[models.ActionTrigger]Subscriber)
		}
		a.Subscribers[action][s.Category()] = s
	}
}
