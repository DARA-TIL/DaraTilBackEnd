package dtoMappers

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/presentation/dto"
)

func ActionRuleToDomain(d dto.ActionRule) models.ActionRule {
	rules := make(map[models.ActionTrigger]bool)

	for k, v := range d.Rules {
		rules[models.ActionTrigger(k)] = v
	}

	return models.ActionRule{
		Action: models.Actions(d.Action),
		Rules:  rules,
	}
}
func ActionRuleToDTO(m models.ActionRule) dto.ActionRule {
	rules := make(map[string]bool)

	for k, v := range m.Rules {
		rules[string(k)] = v
	}

	return dto.ActionRule{
		Action: string(m.Action),
		Rules:  rules,
	}
}

func ActionRulesToDto(m []models.ActionRule) []dto.ActionRule {
	var d []dto.ActionRule
	for _, v := range m {
		d = append(d, ActionRuleToDTO(v))
	}
	return d
}
func ActionRulesToDomain(d []dto.ActionRule) []models.ActionRule {
	var m []models.ActionRule
	for _, v := range d {
		m = append(m, ActionRuleToDomain(v))
	}
	return m
}
