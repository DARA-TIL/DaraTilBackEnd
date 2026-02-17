package models

type Lesson struct {
	ID            int
	Name          string
	Description   string
	ImageUrl      string
	Author        string
	Reward        int
	RequiredLevel int
	Blocks        []LessonBlock
}

type LessonBlock struct {
	ID          int
	Name        string
	ContentType string
	ContentUrl  string
	ContentText string
	LessonID    int
	Position    int
}
type UpdateLessonFields struct {
	Name          *string
	Description   *string
	ImageUrl      *string
	Author        *string
	Reward        *int
	RequiredLevel *int
}
type UpdateLessonBLockFields struct {
	Name        *string
	ContentType *string
	ContentUrl  *string
	ContentText *string
	Position    *int
	LessonID    *int
}
