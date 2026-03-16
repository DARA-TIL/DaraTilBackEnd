package dto

import "DaraTilBackendV2/internal/domain/models"

type Region struct {
	ID               uint                `json:"id"`
	RequiredLevel    int                 `json:"requiredLevel"`
	RegionStatus     string              `json:"regionStatus"`
	Code             string              `json:"code"`
	ImageUrl         string              `json:"imageUrl"`
	Translations     []RegionTranslation `json:"translations"`
	RegionSlang      []RegionSlang       `json:"regionSlang"`
	RegionTraditions []RegionTraditions  `json:"regionTraditions"`
}

type RegionTranslation struct {
	ID          uint            `json:"id"`
	RegionID    uint            `json:"regionId"`
	Language    models.Language `json:"language"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
}

type RegionSlang struct {
	ID           uint                     `json:"id"`
	RegionID     uint                     `json:"regionId"`
	Translations []RegionSlangTranslation `json:"translations"`
}

type RegionSlangTranslation struct {
	ID            uint            `json:"id"`
	RegionSlangID uint            `json:"regionSlangId"`
	Language      models.Language `json:"language"`
	Word          string          `json:"word"`
	Description   string          `json:"description"`
	PronounceURL  string          `json:"pronounceUrl"`
}

type RegionTraditions struct {
	ID           uint                          `json:"id"`
	RegionID     uint                          `json:"regionId"`
	Translations []RegionTraditionsTranslation `json:"translations"`
}

type RegionTraditionsTranslation struct {
	ID                 uint            `json:"id"`
	RegionTraditionsID uint            `json:"regionTraditionsId"`
	Language           models.Language `json:"language"`
	Name               string          `json:"name"`
	Description        string          `json:"description"`
}
