package dtoMappers

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/presentation/dto"
)

func ToSpeechTestResponse(test models.SpeechTest) dto.SpeechTestResponse {
	return dto.SpeechTestResponse{
		ID:         test.ID,
		KzText:     test.KzText,
		RuText:     test.RuText,
		EnText:     test.EnText,
		Difficulty: test.Difficulty,
	}
}

func ToSpeechTestResponses(tests []models.SpeechTest) []dto.SpeechTestResponse {
	responses := make([]dto.SpeechTestResponse, 0, len(tests))

	for _, test := range tests {
		responses = append(responses, ToSpeechTestResponse(test))
	}

	return responses
}

func ToSpeechTestSessionResponse(session models.SpeechTestSession) dto.SpeechTestSessionResponse {
	return dto.SpeechTestSessionResponse{
		ID:           session.ID,
		UserID:       session.UserID,
		SpeechTests:  ToSpeechTestResponses(session.SpeechTests),
		CorrectCount: session.CorrectCount,
		IsEnded:      session.IsEnded,
	}
}

func ToCheckPronounceResponse(result models.SpeechTestResult) dto.CheckPronounceResponse {
	return dto.CheckPronounceResponse{
		Test:       ToSpeechTestResponse(result.SpeechTest),
		AiResponse: result.AiResponse,
		IsCorrect:  result.IsCorrect,
	}
}

func ToSpeechTestSessionResultResponse(result models.SpeechTestSessionResult) dto.SpeechTestSessionResultResponse {
	return dto.SpeechTestSessionResultResponse{
		Session: ToSpeechTestSessionResponse(result.SpeechTestSession),
		Reward:  result.Reward,
	}
}
