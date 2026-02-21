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
}
type TestUpdate struct {
	ID           *uint
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
type Answers struct {
	TestID   uint
	LessonID uint
	UserID   uint
	UserAns  map[uint]uint
}
