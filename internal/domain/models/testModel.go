package models

type QuestionOption struct {
	ID        uint
	IsCorrect bool
	Text      string
}

type Question struct {
	ID      uint
	Text    string
	Options []QuestionOption
}

type Test struct {
	ID        uint
	Questions []Question
	Reward    int
}
