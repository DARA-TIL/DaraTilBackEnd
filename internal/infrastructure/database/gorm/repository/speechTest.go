package repository

import (
	"context"

	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/errhandlers"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels/gormMappers"

	"gorm.io/gorm"
)

type SpeechTestRepository struct {
	db *gorm.DB
}

func NewSpeechTestRepository(db *gorm.DB) *SpeechTestRepository {
	return &SpeechTestRepository{db: db}
}

func (r *SpeechTestRepository) Create(ctx context.Context, test models.SpeechTest) (*models.SpeechTest, error) {
	tg := gormMappers.ToGormSpeechTest(test)

	if err := r.db.WithContext(ctx).Create(&tg).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}

	t := gormMappers.ToDomainSpeechTest(tg)
	return &t, nil
}

func (r *SpeechTestRepository) Update(ctx context.Context, test models.SpeechTest) (*models.SpeechTest, error) {
	tg := gormMappers.ToGormSpeechTest(test)

	if err := r.db.WithContext(ctx).
		Model(&gormModels.SpeechTest{}).
		Where("id = ?", test.ID).
		Updates(map[string]interface{}{
			"kz_text":    tg.KzText,
			"ru_text":    tg.RuText,
			"en_text":    tg.EnText,
			"difficulty": tg.Difficulty,
		}).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}

	updated, err := r.GetByID(ctx, test.ID)
	if err != nil {
		return nil, err
	}

	return updated, nil
}

func (r *SpeechTestRepository) Delete(ctx context.Context, id uint) error {
	if err := r.db.WithContext(ctx).
		Unscoped().
		Delete(&gormModels.SpeechTest{}, id).Error; err != nil {
		return errhandlers.DBErrHandler(err)
	}

	return nil
}

func (r *SpeechTestRepository) GetByID(ctx context.Context, id uint) (*models.SpeechTest, error) {
	var tg gormModels.SpeechTest

	if err := r.db.WithContext(ctx).
		First(&tg, id).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}

	t := gormMappers.ToDomainSpeechTest(tg)
	return &t, nil
}

func (r *SpeechTestRepository) GetAll(ctx context.Context) ([]models.SpeechTest, error) {
	var tg []gormModels.SpeechTest

	if err := r.db.WithContext(ctx).
		Order("created_at DESC").
		Find(&tg).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}

	t := gormMappers.ToDomainSpeechTests(tg)
	return t, nil
}
