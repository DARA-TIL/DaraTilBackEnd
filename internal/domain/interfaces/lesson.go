package interfaces

import "DaraTilBackendV2/internal/domain/models"

type LessonRepo interface {
	Create(lesson models.Lesson) (models.Lesson, error)
	GetAll() ([]models.Lesson, error)
	GetByID(id uint) (models.Lesson, error)
	Update(lesson models.Lesson) (models.Lesson, error)
	Delete(id uint) (models.Lesson, error)

	//blocks
	CreateBlock(block models.LessonBlock) (models.LessonBlock, error)
	UpdateBlock(block models.LessonBlock) (models.LessonBlock, error)
	DeleteBlock(id uint) (models.LessonBlock, error)
}
