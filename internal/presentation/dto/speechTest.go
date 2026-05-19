package dto

import "DaraTilBackendV2/internal/domain/models"

type SpeechTestCreateRequest struct {
	KzText     string                  `json:"kz_text" binding:"required"`
	RuText     string                  `json:"ru_text" binding:"required"`
	EnText     string                  `json:"en_text" binding:"required"`
	Difficulty models.SpeechDifficulty `json:"difficulty" binding:"required,oneof=easy medium hard"`
}

type SpeechTestUpdateRequest struct {
	KzText     string                  `json:"kz_text" binding:"required"`
	RuText     string                  `json:"ru_text" binding:"required"`
	EnText     string                  `json:"en_text" binding:"required"`
	Difficulty models.SpeechDifficulty `json:"difficulty" binding:"required,oneof=easy medium hard"`
}

type SpeechTestResponse struct {
	ID         uint                    `json:"id"`
	KzText     string                  `json:"kz_text"`
	RuText     string                  `json:"ru_text"`
	EnText     string                  `json:"en_text"`
	Difficulty models.SpeechDifficulty `json:"difficulty"`
}

type SpeechTestListResponse struct {
	Items []SpeechTestResponse `json:"items"`
	Total int                  `json:"total"`
}

type SpeechTestSessionResponse struct {
	ID           uint                 `json:"id"`
	UserID       uint                 `json:"user_id"`
	SpeechTests  []SpeechTestResponse `json:"speech_tests"`
	CorrectCount int                  `json:"correct_count"`
	IsEnded      bool                 `json:"is_ended"`
}

type CheckPronounceRequest struct {
	TestID uint `form:"test_id" binding:"required"`
}
type CheckPronounceResponse struct {
	Test       SpeechTestResponse `json:"test"`
	AiResponse string             `json:"ai_response"`
	IsCorrect  bool               `json:"is_correct"`
}

type SpeechTestSessionResultResponse struct {
	Session SpeechTestSessionResponse `json:"session"`
	Reward  int                       `json:"reward"`
}
