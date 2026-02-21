package repo

import (
	"DaraTilBackendV2/internal/domain/models"
	"context"
)

type LessonRepo interface {
	Create(ctx context.Context, lesson models.Lesson) (*models.Lesson, error)
	GetAll(ctx context.Context) ([]models.Lesson, error)
	GetByID(ctx context.Context, id uint) (*models.Lesson, error)
	Update(ctx context.Context, id uint, upd map[string]any) (*models.Lesson, error)
	Delete(ctx context.Context, id uint) error
	FinishLesson(ctx context.Context, lesson models.LessonResult) (*models.LessonResult, error)
	GetFinishedLessons(ctx context.Context, userID uint) ([]models.LessonResult, error)
	GetLessonResults(ctx context.Context, userID, LessonID uint) ([]models.LessonResult, error)
	//blocks
	CreateBlock(ctx context.Context, block models.LessonBlock) (*models.LessonBlock, error)
	UpdateBlock(ctx context.Context, id uint, upd map[string]any, position *int, lessonId *uint) (*models.LessonBlock, error)
	DeleteBlock(ctx context.Context, id uint) error
}
