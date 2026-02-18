package dtoMappers

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/presentation/dto"
)

/* ===========================
   QuestionOption
=========================== */

func DtoQuestionOptionToDomain(opt dto.QuestionOption) models.QuestionOption {
	return models.QuestionOption{
		ID:         opt.ID,
		QuestionID: opt.QuestionID,
		Text:       opt.Text,
	}
}

func QuestionOptionToDto(opt models.QuestionOption) dto.QuestionOption {
	return dto.QuestionOption{
		ID:         opt.ID,
		QuestionID: opt.QuestionID,
		Text:       opt.Text,
	}
}

/* ===========================
   Question
=========================== */

func DtoQuestionToDomain(q dto.Question) models.Question {
	options := make([]models.QuestionOption, 0, len(q.Options))
	for _, opt := range q.Options {
		options = append(options, DtoQuestionOptionToDomain(opt))
	}

	return models.Question{
		ID:      q.ID,
		TestID:  q.TestID,
		Text:    q.Text,
		Options: options,
	}
}

func QuestionToDto(q models.Question) dto.Question {
	options := make([]dto.QuestionOption, 0, len(q.Options))
	for _, opt := range q.Options {
		options = append(options, QuestionOptionToDto(opt))
	}

	return dto.Question{
		ID:      q.ID,
		TestID:  q.TestID,
		Text:    q.Text,
		Options: options,
	}
}

/* ===========================
   Test
=========================== */

func DtoTestToDomain(t dto.Test) models.Test {
	questions := make([]models.Question, 0, len(t.Questions))
	for _, q := range t.Questions {
		questions = append(questions, DtoQuestionToDomain(q))
	}

	return models.Test{
		ID:        t.ID,
		LessonID:  t.LessonID,
		Reward:    t.Reward,
		Questions: questions,
	}
}

func TestToDto(t models.Test) dto.Test {
	questions := make([]dto.Question, 0, len(t.Questions))
	for _, q := range t.Questions {
		questions = append(questions, QuestionToDto(q))
	}

	return dto.Test{
		ID:        t.ID,
		LessonID:  t.LessonID,
		Reward:    t.Reward,
		Questions: questions,
	}
}

/* ===========================
   QuestionOption Update
=========================== */

func DtoQuestionOptionsUpdateToDomain(u dto.QuestionOptionsUpdate) models.QuestionOptionsUpdate {
	return models.QuestionOptionsUpdate{
		ID:        u.ID,
		IsCorrect: u.IsCorrect,
		Text:      u.Text,
	}
}

/* ===========================
   Question Update
=========================== */

func DtoQuestionUpdateToDomain(u dto.QuestionUpdate) models.QuestionUpdate {
	options := make([]models.QuestionOptionsUpdate, 0, len(u.QuestionOptionsUpd))
	for _, opt := range u.QuestionOptionsUpd {
		options = append(options, DtoQuestionOptionsUpdateToDomain(opt))
	}

	return models.QuestionUpdate{
		ID:                 u.ID,
		Text:               u.Text,
		QuestionOptionsUpd: options,
	}
}

/* ===========================
   Test Update
=========================== */

func DtoTestUpdateToDomain(u dto.TestUpdate) models.TestUpdate {
	questions := make([]models.QuestionUpdate, 0, len(u.QuestionsUpd))
	for _, q := range u.QuestionsUpd {
		questions = append(questions, DtoQuestionUpdateToDomain(q))
	}
	return models.TestUpdate{
		ID:           u.ID,
		Reward:       u.Reward,
		QuestionsUpd: questions,
	}
}
