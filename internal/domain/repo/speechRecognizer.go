package repo

import (
	"DaraTilBackendV2/internal/domain/models"
	"context"
	"io"
)

type SpeechRecognizer interface {
	IsCorrectPronounce(ctx context.Context, text string, audio io.Reader) (*models.AiPronounceResponse, error)
}
