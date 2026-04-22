package repository

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/errhandlers"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels/gormMappers"
	"context"

	"gorm.io/gorm"
)

type ActionRuleRepository struct {
	db *gorm.DB
}

func NewActionRuleRepository(db *gorm.DB) *ActionRuleRepository {
	return &ActionRuleRepository{db: db}
}

func (a *ActionRuleRepository) Create(ctx context.Context, actionRule models.ActionRule) error {
	model, err := gormMappers.ToModel(actionRule)
	if err != nil {
		return err
	}

	if err := a.db.WithContext(ctx).Create(&model).Error; err != nil {
		return errhandlers.DBErrHandler(err)
	}

	return nil
}

func (a *ActionRuleRepository) CreateMulti(ctx context.Context, actionRules []models.ActionRule) error {
	var modelsList []gormModels.ActionRule

	for _, rule := range actionRules {
		m, err := gormMappers.ToModel(rule)
		if err != nil {
			return err
		}
		modelsList = append(modelsList, m)
	}

	if err := a.db.WithContext(ctx).Create(&modelsList).Error; err != nil {
		return errhandlers.DBErrHandler(err)
	}

	return nil
}

func (a *ActionRuleRepository) Update(ctx context.Context, actionRule models.ActionRule) error {
	model, err := gormMappers.ToModel(actionRule)
	if err != nil {
		return err
	}

	if err := a.db.WithContext(ctx).
		Where("action = ?", actionRule.Action).
		Updates(&model).Error; err != nil {
		return errhandlers.DBErrHandler(err)
	}

	return nil
}

func (a *ActionRuleRepository) Delete(ctx context.Context, action models.Actions) error {
	if err := a.db.WithContext(ctx).
		Where("action = ?", action).
		Delete(&gormModels.ActionRule{}).Error; err != nil {
		return errhandlers.DBErrHandler(err)
	}

	return nil
}

func (a *ActionRuleRepository) GetAll(ctx context.Context) ([]models.ActionRule, error) {
	var gormRules []gormModels.ActionRule

	if err := a.db.WithContext(ctx).Find(&gormRules).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}

	var result []models.ActionRule

	for _, r := range gormRules {
		domain, err := gormMappers.ActionRuleToDomain(r)
		if err != nil {
			return nil, err
		}
		result = append(result, domain)
	}

	return result, nil
}

func (a *ActionRuleRepository) GetByAction(ctx context.Context, action models.Actions) (models.ActionRule, error) {
	var gormRule gormModels.ActionRule

	if err := a.db.WithContext(ctx).
		Where("action = ?", action).
		First(&gormRule).Error; err != nil {
		return models.ActionRule{}, errhandlers.DBErrHandler(err)
	}

	return gormMappers.ActionRuleToDomain(gormRule)
}
