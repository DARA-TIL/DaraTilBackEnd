package gormModels

import (
	"DaraTilBackendV2/internal/domain/models"

	"gorm.io/gorm"
)

type Region struct {
	gorm.Model
	RequiredLevel    int
	Code             string `gorm:"unique"`
	Kind             string
	IsActive         bool `gorm:"default:true"`
	ImageUrl         string
	Translations     []RegionTranslation `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	RegionSlang      []RegionSlang       `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	RegionTraditions []RegionTraditions  `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
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
	Translations []RegionSlangTranslation `gorm:"foreignKey:RegionSlangID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	Region       Region                   `gorm:"foreignKey:RegionID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
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
	Translations []RegionTraditionsTranslation `gorm:"foreignKey:RegionTraditionsID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	Region       Region                        `gorm:"foreignKey:RegionID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}
type RegionTraditionsTranslation struct {
	gorm.Model
	RegionTraditionsID uint
	Language           models.Language
	Name               string
	Description        string
	RegionTraditions   RegionTraditions `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}
