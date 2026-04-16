package models

type WordRequest struct {
	Word  string
	Block string
}

type WordExplainResult struct {
	WordTranslations           map[Language]string
	WordExplainingTranslations map[Language]string
}
