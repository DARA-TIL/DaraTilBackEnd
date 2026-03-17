package models

type Region struct {
	ID               uint
	Code             string
	Kind             string
	IsActive         bool
	RequiredLevel    int
	ImageUrl         string
	Translations     []RegionTranslation
	RegionSlang      []RegionSlang
	RegionTraditions []RegionTraditions
}

type RegionTranslation struct {
	ID          uint
	RegionID    uint
	Language    Language
	Name        string
	Description string
}
type RegionSlang struct {
	ID           uint
	RegionID     uint
	Translations []RegionSlangTranslation
}
type RegionSlangTranslation struct {
	ID            uint
	RegionSlangID uint
	Language      Language
	Word          string
	Description   string
	PronounceURL  string
}

type RegionTraditions struct {
	ID           uint
	Translations []RegionTraditionsTranslation
	RegionID     uint
}
type RegionTraditionsTranslation struct {
	ID                 uint
	RegionTraditionsID uint
	Language           Language
	Name               string
	Description        string
}
