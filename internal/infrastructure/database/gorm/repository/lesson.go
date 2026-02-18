package repository

import (
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/errhandlers"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels/gormMappers"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"context"

	"gorm.io/gorm"
)

type LessonRepository struct {
	db *gorm.DB
}

func NewLessonRepository(db *gorm.DB) *LessonRepository {
	return &LessonRepository{
		db: db,
	}
}

func (l LessonRepository) Create(ctx context.Context, lesson models.Lesson) (*models.Lesson, error) {
	gormLesson := gormMappers.LessonToGormModel(lesson)
	if err := l.db.WithContext(ctx).Create(&gormLesson).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	lesson = gormMappers.GormLessonToDomainModel(gormLesson)
	return &lesson, nil
}

func (l LessonRepository) GetAll(ctx context.Context) ([]models.Lesson, error) {
	var gormLessons []gormModels.Lesson
	if err := l.db.WithContext(ctx).Preload("Blocks").Find(&gormLessons).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	var lessons []models.Lesson
	for _, l := range gormLessons {
		domLesson := gormMappers.GormLessonToDomainModel(l)
		lessons = append(lessons, domLesson)
	}
	return lessons, nil
}

func (l LessonRepository) GetByID(ctx context.Context, id uint) (*models.Lesson, error) {
	var lesson gormModels.Lesson
	if err := l.db.WithContext(ctx).Preload("Blocks").First(&lesson, id).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	domLesson := gormMappers.GormLessonToDomainModel(lesson)
	return &domLesson, nil
}

func (l LessonRepository) Update(ctx context.Context, id uint, upd map[string]any) (*models.Lesson, error) {
	if err := l.db.Model(&gormModels.Lesson{}).Where("id = ?", id).Updates(upd).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	var lesson gormModels.Lesson
	if err := l.db.WithContext(ctx).Preload("Blocks").First(&lesson, id).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	domLesson := gormMappers.GormLessonToDomainModel(lesson)
	return &domLesson, nil
}

func (l LessonRepository) Delete(ctx context.Context, id uint) error {
	if err := l.db.WithContext(ctx).Delete(&gormModels.Lesson{}, id).Error; err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}

func (l LessonRepository) CreateBlock(ctx context.Context, block models.LessonBlock) (*models.LessonBlock, error) {
	blockGorm := gormMappers.LessonBlockToGormModel(block)
	err := l.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&gormModels.LessonBlock{}).Where("lesson_id = ? AND position >= ?",
			block.LessonID, block.Position).Update("position", gorm.Expr("position + 1")).Error; err != nil {
			return errhandlers.DBErrHandler(err)
		}
		if err := tx.Create(&blockGorm).Error; err != nil {
			return errhandlers.DBErrHandler(err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	block = gormMappers.GormLessonBlockToDomainModel(blockGorm)
	return &block, nil
}

func (l LessonRepository) UpdateBlock(ctx context.Context, id uint, upd map[string]any, position *int, lessonId *uint) (*models.LessonBlock, error) {
	err := l.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if position != nil && lessonId != nil {
			if err := swapPositions(tx, id, *position, *lessonId); err != nil {
				return err
			}
		}
		if err := tx.Model(&gormModels.LessonBlock{}).Where("id = ?", id).Updates(upd).Error; err != nil {
			return errhandlers.DBErrHandler(err)
		}
		if lessonId != nil && position != nil {
			if err := NormalizePositions(tx, *lessonId); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	var bl gormModels.LessonBlock
	if err := l.db.Model(&gormModels.LessonBlock{}).Where("id = ?", id).First(&bl).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	block := gormMappers.GormLessonBlockToDomainModel(bl)
	return &block, nil
}

func (l LessonRepository) DeleteBlock(ctx context.Context, id uint) error {
	err := l.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var block gormModels.LessonBlock
		if err := tx.Where("id = ?", id).First(&block).Error; err != nil {
			return errhandlers.DBErrHandler(err)
		}
		if err := tx.Unscoped().Where("id = ?", id).Delete(&gormModels.LessonBlock{}).Error; err != nil {
			return errhandlers.DBErrHandler(err)
		}
		err := NormalizePositions(tx, block.LessonID)
		if err != nil {
			return errhandlers.DBErrHandler(err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}
func NormalizePositions(tx *gorm.DB, lessonID uint) error {
	logger.Info("NormalizePositions started")

	var blocks []gormModels.LessonBlock
	if err := tx.Where("lesson_id = ?", lessonID).
		Order("position asc, id asc").
		Find(&blocks).Error; err != nil {

		logger.Error("Failed to fetch lesson blocks for normalization")
		return errhandlers.DBErrHandler(err)
	}

	logger.Info("Blocks fetched for normalization")

	for i := range blocks {
		newPos := i + 1

		if blocks[i].Position != newPos {
			logger.Info("Updating block position")

			if err := tx.Model(&gormModels.LessonBlock{}).
				Where("id = ?", blocks[i].ID).
				Update("position", newPos).Error; err != nil {

				logger.Error("Failed to update block position during normalization")
				return errhandlers.DBErrHandler(err)
			}
		}
	}

	logger.Info("NormalizePositions completed successfully")
	return nil
}

func swapPositions(tx *gorm.DB, id uint, position int, lessonID uint) error {
	var updBlock gormModels.LessonBlock
	if err := tx.Model(&gormModels.LessonBlock{}).Where("id = ?", id).First(&updBlock).Error; err != nil {
		return err
	}
	prevPosition := updBlock.Position
	res := tx.Model(&gormModels.LessonBlock{}).Where("lesson_id = ? AND position = ?", lessonID, position).Update("position", prevPosition)
	if res.Error != nil {
		return errs.ErrInternal
	}
	if res.RowsAffected == 0 {
		return errs.ErrBadRequest
	}
	if err := tx.Model(&gormModels.LessonBlock{}).Where("id = ?", id).Update("position", position).Error; err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}
