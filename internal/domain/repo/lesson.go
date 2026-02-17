package repo

import (
	"DaraTilBackendV2/internal/domain/models"
	"context"
)

type LessonRepo interface {
	Create(ctx context.Context, lesson models.Lesson) (*models.Lesson, error)
	GetAll(ctx context.Context) ([]models.Lesson, error)
	GetByID(ctx context.Context, id int) (*models.Lesson, error)
	Update(ctx context.Context, id int, upd map[string]any) (*models.Lesson, error)
	Delete(ctx context.Context, id int) error

	//blocks
	CreateBlock(ctx context.Context, block models.LessonBlock) (*models.LessonBlock, error)
	UpdateBlock(ctx context.Context, id int, upd map[string]any, position, lessonId *int) (*models.LessonBlock, error)
	DeleteBlock(ctx context.Context, id int) error
}
