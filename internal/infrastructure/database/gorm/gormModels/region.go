package gormModels

import (
	"DaraTilBackendV2/internal/domain/models"

	"gorm.io/gorm"
)

type Region struct {
	gorm.Model
	RequiredLevel    int
	Code             string `gorm:"unique"`
	ImageUrl         string
	Translations     []RegionTranslation
	RegionSlang      []RegionSlang
	RegionTraditions []RegionTraditions
}
type RegionTranslation struct {
	gorm.Model
	RegionID    uint
	Language    models.Language
	Name        string
	Description string
	Region      Region `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}
type RegionSlang struct {
	gorm.Model
	RegionID     uint
	Translations []RegionSlangTranslation
	Region       Region `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}
type RegionSlangTranslation struct {
	gorm.Model
	RegionSlangID uint
	Language      models.Language
	Word          string
	Description   string
	PronounceURL  string
	RegionSlang   RegionSlang `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}

type RegionTraditions struct {
	gorm.Model
	RegionID     uint
	Translations []RegionTraditionsTranslation
	Region       Region `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}
type RegionTraditionsTranslation struct {
	gorm.Model
	RegionTraditionsID uint
	Language           models.Language
	Name               string
	Description        string
	RegionTraditions   RegionTraditions `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}
