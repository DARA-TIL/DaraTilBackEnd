package folkloreUC

type folkloreRequest struct {
	type Folklore struct {
	gorm.Model
	Type         string                `json:"type" gorm:"not null"`
	Author       string                `json:"author" gorm:"not null"`
	Region       string                `json:"region" gorm:"not null"`
	Content      string                `json:"content" gorm:""`
	Name         string                `json:"name" gorm:""`
	MediaUrl     string                `json:"mediaUrl"`
	ImageUrl     string                `json:"imageUrl"`
	LikesCount   int                   `json:"likesCount" gorm:"default:0"`
	Likes        []FolkloreLike        `gorm:"constraint:OnDelete:CASCADE;"`
	Translations []FolkloreTranslation `json:"translations" gorm:"constraint:OnDelete:CASCADE;"`
}

	type FolkloreTranslation struct {
	gorm.Model
	FolkloreID  uint   `json:"folkloreID" gorm:"not null"`
	Language    string `json:"language" gorm:"not null"`
	Name        string `json:"name" gorm:"not null"`
	Content     string `json:"content" gorm:"not null"`
	Explanation string `json:"explanation" gorm:"not null"`
}
}
