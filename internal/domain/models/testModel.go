package models

type QuestionOption struct {
	ID         uint
	QuestionID uint
	IsCorrect  bool
	Text       string
}

type Question struct {
	ID      uint
	TestID  uint
	Text    string
	Options []QuestionOption
}

type Test struct {
	ID        uint
	LessonID  uint
	Questions []Question
	Reward    int
}
type TestUpdate struct {
	ID           *uint
	Reward       *uint
	QuestionsUpd []QuestionUpdate
}
type QuestionUpdate struct {
	ID                 *uint
	Text               *string
	QuestionOptionsUpd []QuestionOptionsUpdate
}
type QuestionOptionsUpdate struct {
	ID        *uint
	IsCorrect *bool
	Text      *string
}
