package repo

import (
	"DaraTilBackendV2/internal/domain/models"
	"context"
)

type SpeechTestRepo interface {
	Create(ctx context.Context, test models.SpeechTest) (*models.SpeechTest, error)
	Update(ctx context.Context, test models.SpeechTest) (*models.SpeechTest, error)
	Delete(ctx context.Context, id uint) error
	GetByID(ctx context.Context, id uint) (*models.SpeechTest, error)
	GetAll(ctx context.Context) ([]models.SpeechTest, error)
}
type SpeechTestSession interface {
	Create(ctx context.Context, session models.SpeechTestSession) (*models.SpeechTestSession, error)
	GetActiveByUserID(ctx context.Context, userID uint) (*models.SpeechTestSession, error)
	AddRandomNewTestToActiveSession(ctx context.Context, userID uint) (*models.SpeechTest, error)
	AddRandomNewTestToSession(ctx context.Context, sessionID uint) (*models.SpeechTest, error)
	EndActiveSession(ctx context.Context, userID uint) error
	IncreaseCorrectCount(ctx context.Context, userID uint) error
}
