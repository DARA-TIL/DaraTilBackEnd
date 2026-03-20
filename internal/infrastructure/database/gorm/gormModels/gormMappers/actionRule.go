package gormMappers

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
	"encoding/json"
)

func ActionRuleToDomain(m gormModels.ActionRule) (models.ActionRule, error) {
	var rules map[models.ActionTrigger]bool

	if err := json.Unmarshal(m.Rules, &rules); err != nil {
		return models.ActionRule{}, err
	}

	return models.ActionRule{
		Action: models.Actions(m.Action),
		Rules:  rules,
	}, nil
}
func ToModel(d models.ActionRule) (gormModels.ActionRule, error) {
	data, err := json.Marshal(d.Rules)
	if err != nil {
		return gormModels.ActionRule{}, err
	}

	return gormModels.ActionRule{
		Action: string(d.Action),
		Rules:  data,
	}, nil
}
