package gormMappers

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
)

func LessonToGormModel(lesson models.Lesson) gormModels.Lesson {
	return gormModels.Lesson{
		Name:          lesson.Name,
		Description:   lesson.Description,
		ImageUrl:      lesson.ImageUrl,
		Author:        lesson.Author,
		Reward:        lesson.Reward,
		RequiredLevel: lesson.RequiredLevel,
		Blocks:        LessonBlocksToGormModel(lesson.Blocks),
	}
}

func LessonBlocksToGormModel(blocks []models.LessonBlock) []gormModels.LessonBlock {
	var blocksGorm []gormModels.LessonBlock

	for _, block := range blocks {
		gormBlock := gormModels.LessonBlock{
			Name:        block.Name,
			ContentType: block.ContentType,
			ContentUrl:  block.ContentUrl,
			ContentText: block.ContentText,
			LessonID:    block.LessonID,
			Position:    block.Position,
		}

		blocksGorm = append(blocksGorm, gormBlock)
	}

	return blocksGorm
}

func GormLessonToDomainModel(lesson gormModels.Lesson) models.Lesson {
	return models.Lesson{
		ID:            int(lesson.ID),
		Name:          lesson.Name,
		Description:   lesson.Description,
		ImageUrl:      lesson.ImageUrl,
		Author:        lesson.Author,
		Reward:        lesson.Reward,
		RequiredLevel: lesson.RequiredLevel,
		Blocks:        GormLessonBlocksToDomainModel(lesson.Blocks),
	}
}

func GormLessonBlocksToDomainModel(blocks []gormModels.LessonBlock) []models.LessonBlock {
	var blocksDomain []models.LessonBlock

	for _, block := range blocks {
		domainBlock := models.LessonBlock{
			ID:          int(block.ID),
			Name:        block.Name,
			ContentType: block.ContentType,
			ContentUrl:  block.ContentUrl,
			ContentText: block.ContentText,
			LessonID:    block.LessonID,
			Position:    block.Position,
		}

		blocksDomain = append(blocksDomain, domainBlock)
	}

	return blocksDomain
}
func LessonBlockToGormModel(block models.LessonBlock) gormModels.LessonBlock {
	return gormModels.LessonBlock{
		Name:        block.Name,
		ContentType: block.ContentType,
		ContentUrl:  block.ContentUrl,
		ContentText: block.ContentText,
		LessonID:    block.LessonID,
		Position:    block.Position,
	}
}
func GormLessonBlockToDomainModel(block gormModels.LessonBlock) models.LessonBlock {
	return models.LessonBlock{
		ID:          int(block.ID),
		Name:        block.Name,
		ContentType: block.ContentType,
		ContentUrl:  block.ContentUrl,
		ContentText: block.ContentText,
		LessonID:    block.LessonID,
		Position:    block.Position,
	}
}
