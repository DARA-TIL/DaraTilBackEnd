package dto

type QuestionOption struct {
	ID         uint   `json:"id,omitempty"`
	QuestionID uint   `json:"questionId,omitempty"`
	Text       string `json:"text,omitempty"`
	IsCorrect  bool   `json:"isCorrect,omitempty"`
}
type Question struct {
	ID      uint             `json:"id,omitempty"`
	TestID  uint             `json:"testId,omitempty"`
	Text    string           `json:"text,omitempty"`
	Options []QuestionOption `json:"options,omitempty"`
}
type Test struct {
	ID        uint       `json:"id,omitempty"`
	LessonID  uint       `json:"lessonId,omitempty"`
	Questions []Question `json:"questions,omitempty"`
}
type TestUpdate struct {
	ID           *uint            `json:"id,omitempty"`
	Reward       *uint            `json:"reward,omitempty"`
	QuestionsUpd []QuestionUpdate `json:"questionsUpd,omitempty"`
}
type QuestionUpdate struct {
	ID                 *uint                   `json:"id,omitempty"`
	Text               *string                 `json:"text,omitempty"`
	QuestionOptionsUpd []QuestionOptionsUpdate `json:"questionOptionsUpd,omitempty"`
}
type QuestionOptionsUpdate struct {
	ID        *uint   `json:"id,omitempty"`
	IsCorrect *bool   `json:"isCorrect,omitempty"`
	Text      *string `json:"text,omitempty"`
}

type UserAnswers struct {
	TestID   uint          `json:"testId,omitempty"`
	LessonID uint          `json:"lessonId,omitempty"`
	UserID   uint          `json:"userId,omitempty"`
	UserAns  map[uint]uint `json:"userAns,omitempty"`
}
