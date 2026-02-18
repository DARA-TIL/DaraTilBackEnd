package gormMappers

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
)

func GormTestToDomain(test gormModels.Test) models.Test {
	var qs []models.Question
	for _, q := range test.Questions {
		qs = append(qs, GormQuestionToDomain(q))
	}
	return models.Test{
		ID:        test.ID,
		LessonID:  test.LessonID,
		Questions: qs,
		Reward:    test.Reward,
	}
}
func GormQuestionToDomain(question gormModels.Question) models.Question {
	var qos []models.QuestionOption
	for _, q := range question.Options {
		qos = append(qos, GormQuestionOptionToDomain(q))
	}
	return models.Question{
		ID:      question.ID,
		TestID:  question.TestID,
		Text:    question.Text,
		Options: qos,
	}
}

func GormQuestionOptionToDomain(qo gormModels.QuestionOption) models.QuestionOption {
	return models.QuestionOption{
		ID:         qo.ID,
		QuestionID: qo.QuestionID,
		IsCorrect:  qo.IsCorrect,
		Text:       qo.Text,
	}
}

func TestToGorm(test models.Test) gormModels.Test {
	var qs []gormModels.Question
	for _, q := range test.Questions {
		qs = append(qs, QuestionToGorm(q))
	}
	return gormModels.Test{
		LessonID:  test.LessonID,
		Questions: qs,
		Reward:    test.Reward,
	}
}
func QuestionToGorm(question models.Question) gormModels.Question {
	var qos []gormModels.QuestionOption
	for _, q := range question.Options {
		qos = append(qos, QuestionOptionToGorm(q))
	}
	return gormModels.Question{
		TestID:  question.TestID,
		Text:    question.Text,
		Options: qos,
	}
}

func QuestionOptionToGorm(qo models.QuestionOption) gormModels.QuestionOption {
	return gormModels.QuestionOption{
		QuestionID: qo.QuestionID,
		IsCorrect:  qo.IsCorrect,
		Text:       qo.Text,
	}
}
