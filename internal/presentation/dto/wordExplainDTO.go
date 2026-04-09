package dto

type WordExplain struct {
	Word  string `json:"word"`
	Block string `json:"block"`
	Lang  string `json:"lang"`
}

type WordExplainResult struct {
	Result  string `json:"result"`
	Context string `json:"context"`
}
