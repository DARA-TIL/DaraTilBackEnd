package repo

import (
	"DaraTilBackendV2/internal/domain/models"
	"context"
)

type TestRepo interface {
	Create(ctx context.Context, test models.Test) (*models.Test, error)
	CreateQuestion(ctx context.Context, question models.Question) (*models.Question, error)
	CreateOption(ctx context.Context, option models.QuestionOption) (*models.QuestionOption, error)
	Update(ctx context.Context, upd models.TestUpdate) (*models.Test, error)
	GetById(ctx context.Context, id uint) (*models.Test, error)
	GetByLessonId(ctx context.Context, id uint) (*models.Test, error)
	GetOptionByID(ctx context.Context, id uint) (*models.QuestionOption, error)
	Delete(ctx context.Context, id uint) error
	DeleteQuestion(ctx context.Context, id uint) error
	DeleteOption(ctx context.Context, id uint) error
	UpdateQuestion(ctx context.Context, upd models.QuestionUpdate) (*models.Question, error)
	UpdateQuestionOption(ctx context.Context, upd models.QuestionOptionsUpdate) (*models.QuestionOption, error)
}
