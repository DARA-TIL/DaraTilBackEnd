package repository

import (
	"context"

	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/errhandlers"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels/gormMappers"

	"gorm.io/gorm"
)

type SpeechTestSessionRepository struct {
	db *gorm.DB
}

func NewSpeechTestSessionRepository(db *gorm.DB) *SpeechTestSessionRepository {
	return &SpeechTestSessionRepository{db: db}
}

// Create creates only an empty speech test session.
// It does not attach speech tests.
func (r *SpeechTestSessionRepository) Create(
	ctx context.Context,
	session models.SpeechTestSession,
) (*models.SpeechTestSession, error) {
	sg := gormMappers.ToGormSpeechTestSession(session)

	if err := r.db.WithContext(ctx).Create(&sg).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}

	var created gormModels.SpeechTestSession
	if err := r.db.WithContext(ctx).
		Preload("User").
		First(&created, sg.ID).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}

	result := gormMappers.ToDomainSpeechTestSession(created)
	return &result, nil
}

func (r *SpeechTestSessionRepository) GetActiveByUserID(
	ctx context.Context,
	userID uint,
) (*models.SpeechTestSession, error) {
	var sg gormModels.SpeechTestSession

	if err := r.db.WithContext(ctx).
		Preload("SessionTests.Test").
		Preload("User").
		Where("user_id = ? AND is_ended = ?", userID, false).
		Order("created_at DESC").
		First(&sg).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}

	session := gormMappers.ToDomainSpeechTestSession(sg)
	return &session, nil
}

func (r *SpeechTestSessionRepository) AddRandomNewTestToActiveSession(
	ctx context.Context,
	userID uint,
) (*models.SpeechTest, error) {
	var result *models.SpeechTest

	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var session gormModels.SpeechTestSession

		if err := tx.
			Where("user_id = ? AND is_ended = ?", userID, false).
			Order("created_at DESC").
			First(&session).Error; err != nil {
			return errhandlers.DBErrHandler(err)
		}

		var test gormModels.SpeechTest

		if err := tx.
			Where(`
				id NOT IN (
					SELECT test_id
					FROM speech_test_session_tests
					WHERE session_id = ?
				)
			`, session.ID).
			Order("RANDOM()").
			First(&test).Error; err != nil {
			return errhandlers.DBErrHandler(err)
		}

		sessionTest := gormModels.SpeechTestSessionTest{
			SessionID: session.ID,
			TestID:    test.ID,
			IsShown:   true,
		}

		if err := tx.Create(&sessionTest).Error; err != nil {
			return errhandlers.DBErrHandler(err)
		}

		domainTest := gormMappers.ToDomainSpeechTest(test)
		result = &domainTest

		return nil
	})

	if err != nil {
		return nil, err
	}

	return result, nil
}

func (r *SpeechTestSessionRepository) AddRandomNewTestToSession(
	ctx context.Context,
	sessionID uint,
) (*models.SpeechTest, error) {
	var result *models.SpeechTest

	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var session gormModels.SpeechTestSession

		if err := tx.
			Where("id = ? AND is_ended = ?", sessionID, false).
			First(&session).Error; err != nil {
			return errhandlers.DBErrHandler(err)
		}

		var test gormModels.SpeechTest

		if err := tx.
			Where(`
				id NOT IN (
					SELECT test_id
					FROM speech_test_session_tests
					WHERE session_id = ?
				)
			`, session.ID).
			Order("RANDOM()").
			First(&test).Error; err != nil {
			return errhandlers.DBErrHandler(err)
		}

		sessionTest := gormModels.SpeechTestSessionTest{
			SessionID: session.ID,
			TestID:    test.ID,
			IsShown:   true,
		}

		if err := tx.Create(&sessionTest).Error; err != nil {
			return errhandlers.DBErrHandler(err)
		}

		domainTest := gormMappers.ToDomainSpeechTest(test)
		result = &domainTest

		return nil
	})

	if err != nil {
		return nil, err
	}

	return result, nil
}

func (r *SpeechTestSessionRepository) EndActiveSession(
	ctx context.Context,
	userID uint,
) error {
	if err := r.db.WithContext(ctx).
		Model(&gormModels.SpeechTestSession{}).
		Where("user_id = ? AND is_ended = ?", userID, false).
		Update("is_ended", true).Error; err != nil {
		return errhandlers.DBErrHandler(err)
	}

	return nil
}

func (r *SpeechTestSessionRepository) IncreaseCorrectCount(
	ctx context.Context,
	userID uint,
) error {
	if err := r.db.WithContext(ctx).
		Model(&gormModels.SpeechTestSession{}).
		Where("user_id = ? AND is_ended = ?", userID, false).
		UpdateColumn("correct_count", gorm.Expr("correct_count + ?", 1)).
		Error; err != nil {
		return errhandlers.DBErrHandler(err)
	}

	return nil
}
