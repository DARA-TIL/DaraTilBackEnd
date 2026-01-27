package models

type Folklore struct {
	ID           uint
	Type         string
	Author       string
	Region       string
	Content      string
	Name         string
	MediaUrl     string
	ImageUrl     string
	LikesCount   int
	Likes        []FolkloreLike
	Translations []FolkloreTranslation
}

type FolkloreTranslation struct {
	ID          uint
	Language    string
	Name        string
	Content     string
	Explanation string
}

type TranslationObj struct {
	NameKz        string
	NameRu        string
	NameEn        string
	ContentKz     string
	ContentRu     string
	ContentEn     string
	ExplanationKz string
	ExplanationRu string
	ExplanationEn string
}
type FolkloreFilter struct {
	Type     string `form:"type"`     // ?type=proverb
	Region   string `form:"region"`   // ?region=Almaty
	Author   string `form:"author"`   // ?author=Abai
	Search   string `form:"search"`   // ?search=батыр (full text search)
	MinLikes int    `form:"minLikes"` // ?minLikes=10
}
