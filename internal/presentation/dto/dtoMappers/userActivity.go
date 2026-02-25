package dtoMappers

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/presentation/dto"
)

func UserActivityToDTO(act models.UserActivity) dto.UserActivityDTO {
	return dto.UserActivityDTO{
		ID:         act.ID,
		Time:       act.Time,
		EntityType: act.EntityType,
		EntityID:   act.EntityID,
		Action:     act.Action,
		UserID:     act.UserID,
	}
}

func UserActivitiesToDTO(act []models.UserActivity) []dto.UserActivityDTO {
	var dtos []dto.UserActivityDTO
	for _, a := range act {
		dtos = append(dtos, UserActivityToDTO(a))
	}
	return dtos
}
