package repo

import (
	"DaraTilBackendV2/internal/domain/models"
	"context"
)

type ActionRuleRepo interface {
	Create(ctx context.Context, actionRule models.ActionRule) error
	CreateMulti(ctx context.Context, actionRules []models.ActionRule) error
	Update(ctx context.Context, actionRule models.ActionRule) error
	Delete(ctx context.Context, action models.Actions) error
	GetAll(ctx context.Context) ([]models.ActionRule, error)
	GetByAction(ctx context.Context, action models.Actions) (models.ActionRule, error)
}
