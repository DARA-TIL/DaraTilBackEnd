package models

type Word struct {
	ID                         uint
	OriginalWord               string
	Context                    string
	WordTranslations           map[Language]string
	WordExplainingTranslations map[Language]string
}
