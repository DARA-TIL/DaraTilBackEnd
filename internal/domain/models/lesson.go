package models

type Lesson struct {
	ID            uint
	Name          string
	Description   string
	ImageUrl      string
	Author        string
	Reward        int
	RequiredLevel int
	Blocks        []LessonBlock
}

type LessonBlock struct {
	ID          uint
	Name        string
	ContentType string
	ContentUrl  string
	ContentText string
	LessonID    uint
	Position    int
}
