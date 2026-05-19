package testSpeechUC

import (
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type TestSpeechUC struct {
	repo repo.SpeechTestRepo
}

func NewTestSpeechUC(repo repo.SpeechTestRepo) *TestSpeechUC {
	return &TestSpeechUC{repo: repo}
}

func (uc *TestSpeechUC) Create(ctx context.Context, test models.SpeechTest) (*models.SpeechTest, error) {
	return uc.repo.Create(ctx, test)
}

func (uc *TestSpeechUC) GetByID(ctx context.Context, id uint) (*models.SpeechTest, error) {
	return uc.repo.GetByID(ctx, id)
}
func (uc *TestSpeechUC) GetAll(ctx context.Context) ([]models.SpeechTest, error) {
	return uc.repo.GetAll(ctx)
}
func (uc *TestSpeechUC) Delete(ctx context.Context, id uint) error {
	return uc.repo.Delete(ctx, id)
}
func (uc *TestSpeechUC) Update(ctx context.Context, id uint, test models.SpeechTest) (*models.SpeechTest, error) {
	if id == 0 {
		return nil, errs.ErrInvalidInput
	}
	test.ID = id
	return uc.repo.Update(ctx, test)
}
