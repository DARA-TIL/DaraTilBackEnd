package dtoMappers

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/presentation/dto"
)

func LessonToDTO(lesson models.Lesson) dto.LessonDTO {
	return dto.LessonDTO{
		ID:            lesson.ID,
		Name:          lesson.Name,
		Description:   lesson.Description,
		ImageUrl:      lesson.ImageUrl,
		Author:        lesson.Author,
		Reward:        lesson.Reward,
		RequiredLevel: lesson.RequiredLevel,
		Blocks:        LessonBlocksToDTO(lesson.Blocks),
	}
}

func LessonsToDTO(lessons []models.Lesson) []dto.LessonDTO {
	var result []dto.LessonDTO
	for _, lesson := range lessons {
		result = append(result, LessonToDTO(lesson))
	}
	return result
}

func LessonBlockToDTO(block models.LessonBlock) dto.LessonBlockDTO {
	return dto.LessonBlockDTO{
		ID:          block.ID,
		Name:        block.Name,
		ContentType: block.ContentType,
		ContentUrl:  block.ContentUrl,
		ContentText: block.ContentText,
		LessonID:    block.LessonID,
		Position:    block.Position,
	}
}

func LessonBlocksToDTO(blocks []models.LessonBlock) []dto.LessonBlockDTO {
	var result []dto.LessonBlockDTO
	for _, block := range blocks {
		result = append(result, LessonBlockToDTO(block))
	}
	return result
}
func UpdateLessonDTOToDomain(dto dto.UpdateLessonDTO) models.UpdateLessonFields {
	return models.UpdateLessonFields{
		Name:          dto.Name,
		Description:   dto.Description,
		ImageUrl:      dto.ImageUrl,
		Author:        dto.Author,
		Reward:        dto.Reward,
		RequiredLevel: dto.RequiredLevel,
	}
}
func UpdateLessonBlockDTOToDomain(dto dto.UpdateLessonBlockDTO) models.UpdateLessonBLockFields {
	return models.UpdateLessonBLockFields{
		Name:        dto.Name,
		ContentType: dto.ContentType,
		ContentUrl:  dto.ContentUrl,
		ContentText: dto.ContentText,
		Position:    dto.Position,
		LessonID:    dto.LessonID,
	}
}
func LessonDTOToDomain(dto dto.LessonDTO) models.Lesson {
	return models.Lesson{
		ID:            dto.ID,
		Name:          dto.Name,
		Description:   dto.Description,
		ImageUrl:      dto.ImageUrl,
		Author:        dto.Author,
		Reward:        dto.Reward,
		RequiredLevel: dto.RequiredLevel,
		Blocks:        LessonBlocksDTOToDomain(dto.Blocks),
	}
}
func LessonsDTOToDomain(dtos []dto.LessonDTO) []models.Lesson {
	var result []models.Lesson
	for _, lesson := range dtos {
		result = append(result, LessonDTOToDomain(lesson))
	}
	return result
}
func LessonBlockDTOToDomain(dto dto.LessonBlockDTO) models.LessonBlock {
	return models.LessonBlock{
		ID:          dto.ID,
		Name:        dto.Name,
		ContentType: dto.ContentType,
		ContentUrl:  dto.ContentUrl,
		ContentText: dto.ContentText,
		LessonID:    dto.LessonID,
		Position:    dto.Position,
	}
}
func LessonBlocksDTOToDomain(dto []dto.LessonBlockDTO) []models.LessonBlock {
	var result []models.LessonBlock
	for _, block := range dto {
		result = append(result, LessonBlockDTOToDomain(block))
	}
	return result
}
