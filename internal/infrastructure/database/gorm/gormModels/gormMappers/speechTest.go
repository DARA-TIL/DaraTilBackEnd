package gormMappers

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"

	"gorm.io/gorm"
)

func ToDomainSpeechTest(entity gormModels.SpeechTest) models.SpeechTest {
	return models.SpeechTest{
		ID:         entity.ID,
		KzText:     entity.KzText,
		RuText:     entity.RuText,
		EnText:     entity.EnText,
		Difficulty: entity.Difficulty,
	}
}

func ToDomainSpeechTests(entities []gormModels.SpeechTest) []models.SpeechTest {
	result := make([]models.SpeechTest, 0, len(entities))

	for _, entity := range entities {
		result = append(result, ToDomainSpeechTest(entity))
	}

	return result
}

func ToGormSpeechTest(domain models.SpeechTest) gormModels.SpeechTest {
	return gormModels.SpeechTest{
		Model: gorm.Model{
			ID: domain.ID,
		},
		KzText:     domain.KzText,
		RuText:     domain.RuText,
		EnText:     domain.EnText,
		Difficulty: domain.Difficulty,
	}
}

func ToGormSpeechTests(domains []models.SpeechTest) []gormModels.SpeechTest {
	result := make([]gormModels.SpeechTest, 0, len(domains))

	for _, domain := range domains {
		result = append(result, ToGormSpeechTest(domain))
	}

	return result
}
func ToDomainSpeechTestSession(entity gormModels.SpeechTestSession) models.SpeechTestSession {
	speechTests := make([]models.SpeechTest, 0, len(entity.SessionTests))

	for _, sessionTest := range entity.SessionTests {
		if sessionTest.Test.ID == 0 {
			continue
		}

		speechTests = append(speechTests, ToDomainSpeechTest(sessionTest.Test))
	}

	return models.SpeechTestSession{
		ID:           entity.ID,
		UserID:       entity.UserID,
		SpeechTests:  speechTests,
		CorrectCount: entity.CorrectCount,
		IsEnded:      entity.IsEnded,
		User:         GormUserToDomain(entity.User),
	}
}

func ToDomainSpeechTestSessions(entities []gormModels.SpeechTestSession) []models.SpeechTestSession {
	result := make([]models.SpeechTestSession, 0, len(entities))

	for _, entity := range entities {
		result = append(result, ToDomainSpeechTestSession(entity))
	}

	return result
}

func ToGormSpeechTestSession(domain models.SpeechTestSession) gormModels.SpeechTestSession {
	return gormModels.SpeechTestSession{
		Model: gorm.Model{
			ID: domain.ID,
		},
		UserID:       domain.UserID,
		CorrectCount: domain.CorrectCount,
		IsEnded:      domain.IsEnded,
		User:         UserToGormModel(domain.User),
	}
}

func ToGormSpeechTestSessions(domains []models.SpeechTestSession) []gormModels.SpeechTestSession {
	result := make([]gormModels.SpeechTestSession, 0, len(domains))

	for _, domain := range domains {
		result = append(result, ToGormSpeechTestSession(domain))
	}

	return result
}
