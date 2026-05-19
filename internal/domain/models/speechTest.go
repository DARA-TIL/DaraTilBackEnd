package models

type SpeechDifficulty string

const (
	SpeechDifficultyHard   SpeechDifficulty = "hard"
	SpeechDifficultyEasy   SpeechDifficulty = "easy"
	SpeechDifficultyMedium SpeechDifficulty = "medium"
)

type SpeechTest struct {
	ID         uint
	KzText     string
	RuText     string
	EnText     string
	Difficulty SpeechDifficulty
}

type SpeechTestSession struct {
	ID           uint
	UserID       uint
	SpeechTests  []SpeechTest
	CorrectCount int
	IsEnded      bool
	User         User
}
type SpeechTestResult struct {
	SpeechTest SpeechTest
	AiResponse string
	IsCorrect  bool
}

type AiPronounceResponse struct {
	IsCorrectPronounce bool
	Explanation        string
}

type SpeechTestSessionResult struct {
	SpeechTestSession SpeechTestSession
	Reward            int
}
