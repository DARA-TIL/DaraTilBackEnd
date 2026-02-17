package dto

type LessonDTO struct {
	ID            int              `json:"id"`
	Name          string           `json:"name"`
	Description   string           `json:"description"`
	ImageUrl      string           `json:"imageUrl"`
	Author        string           `json:"author"`
	Reward        int              `json:"reward"`
	RequiredLevel int              `json:"requiredLevel"`
	Blocks        []LessonBlockDTO `json:"blocks"`
}

type LessonBlockDTO struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	ContentType string `json:"contentType"`
	ContentUrl  string `json:"contentUrl"`
	ContentText string `json:"contentText"`
	LessonID    int    `json:"lessonId"`
	Position    int    `json:"position"`
}

type UpdateLessonDTO struct {
	Name          *string `json:"name,omitempty"`
	Description   *string `json:"description,omitempty"`
	ImageUrl      *string `json:"imageUrl,omitempty"`
	Author        *string `json:"author,omitempty"`
	Reward        *int    `json:"reward,omitempty"`
	RequiredLevel *int    `json:"requiredLevel,omitempty"`
}

type UpdateLessonBlockDTO struct {
	Name        *string `json:"name,omitempty"`
	ContentType *string `json:"contentType,omitempty"`
	ContentUrl  *string `json:"contentUrl,omitempty"`
	ContentText *string `json:"contentText,omitempty"`
	Position    *int    `json:"position,omitempty"`
	LessonID    *int    `json:"lessonID"`
}
