package dto

type FolkloreDTO struct {
	ID           uint                     `json:"id"`
	Type         string                   `json:"type"`
	Author       string                   `json:"author"`
	Region       string                   `json:"region"`
	Content      string                   `json:"content"`
	Name         string                   `json:"name"`
	MediaUrl     string                   `json:"mediaUrl"`
	ImageUrl     string                   `json:"imageUrl"`
	LikesCount   int                      `json:"likesCount"`
	Translations []FolkloreTranslationDTO `json:"translations"`
}

type FolkloreTranslationDTO struct {
	ID          uint   `json:"id"`
	FolkloreID  uint   `json:"folkloreID"`
	Language    string `json:"language"`
	Name        string `json:"name"`
	Content     string `json:"content"`
	Explanation string `json:"explanation"`
}
type UpdatableFolkloreFieldsDTO struct {
	Type         *string                  `json:"type"`
	Author       *string                  `json:"author"`
	Region       *string                  `json:"region"`
	Content      *string                  `json:"content"`
	Name         *string                  `json:"name"`
	MediaUrl     *string                  `json:"mediaUrl"`
	ImageUrl     *string                  `json:"imageUrl"`
	Translations []FolkloreTranslationDTO `json:"translations"`
}
