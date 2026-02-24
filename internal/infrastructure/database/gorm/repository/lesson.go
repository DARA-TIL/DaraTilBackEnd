package repository

import (
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/errhandlers"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels/gormMappers"
	"context"
	"errors"
	"time"

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
	if err := l.db.WithContext(ctx).Order("required_level").Preload("Blocks").Find(&gormLessons).Error; err != nil {
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
	if err := l.db.WithContext(ctx).Preload("Blocks").
		Preload("Test").
		Preload("Test.Questions").
		Preload("Test.Questions.Options").First(&lesson, id).Error; err != nil {
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

func (l LessonRepository) FinishLesson(ctx context.Context, lessonRes models.LessonResult) (*models.LessonResult, error) {
	lessonRes.PassTime = time.Now()
	gormLF := gormMappers.LessonResultToGorm(lessonRes)
	if err := l.db.WithContext(ctx).Create(&gormLF).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	lessonRes = gormMappers.GormLessonResultToDomain(gormLF)
	return &lessonRes, nil
}
func (l LessonRepository) GetFinishedLessons(ctx context.Context, userID uint) ([]models.LessonResult, error) {
	subQuery := l.db.
		Model(&gormModels.LessonResult{}).
		Select("lesson_id, MAX(result) as max_result").
		Where("user_id = ?", userID).
		Group("lesson_id")

	var bestResults []gormModels.LessonResult
	err := l.db.WithContext(ctx).
		Model(&gormModels.LessonResult{}).
		Joins("JOIN (?) as best ON lesson_results.lesson_id = best.lesson_id AND lesson_results.result = best.max_result", subQuery).
		Where("lesson_results.user_id = ?", userID).
		Find(&bestResults).Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	var finLes []models.LessonResult
	for _, lesson := range bestResults {
		finLes = append(finLes, gormMappers.GormLessonResultToDomain(lesson))
	}
	return finLes, nil
}
func (l LessonRepository) GetLessonResults(ctx context.Context, userID, LessonID uint) ([]models.LessonResult, error) {
	var results []gormModels.LessonResult
	if err := l.db.WithContext(ctx).Order("pass_time").Where("user_id = ? AND lesson_id = ?", userID, LessonID).Find(&results).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	var finLes []models.LessonResult
	for _, lesson := range results {
		finLes = append(finLes, gormMappers.GormLessonResultToDomain(lesson))
	}
	return finLes, nil
}

func (l LessonRepository) GetBestResultForLesson(ctx context.Context, userID, lessonID uint) (*models.LessonResult, error) {
	var result gormModels.LessonResult
	err := l.db.WithContext(ctx).
		Where("user_id = ? AND lesson_id = ? AND pass = ?", userID, lessonID, true).
		Order("result DESC").
		Limit(1).
		First(&result).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errs.ErrNotFound
		}
		return nil, errhandlers.DBErrHandler(err)
	}
	resultDom := gormMappers.GormLessonResultToDomain(result)
	return &resultDom, nil
}

func NormalizePositions(tx *gorm.DB, lessonID uint) error {
	var blocks []gormModels.LessonBlock
	if err := tx.Where("lesson_id = ?", lessonID).
		Order("position asc, id asc").
		Find(&blocks).Error; err != nil {
		return errhandlers.DBErrHandler(err)
	}

	for i := range blocks {
		newPos := i + 1

		if blocks[i].Position != newPos {
			if err := tx.Model(&gormModels.LessonBlock{}).
				Where("id = ?", blocks[i].ID).
				Update("position", newPos).Error; err != nil {

				return errhandlers.DBErrHandler(err)
			}
		}
	}

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
