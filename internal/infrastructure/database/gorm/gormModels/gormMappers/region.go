package gormMappers

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
)

func RegionToGormModel(region models.Region) gormModels.Region {
	return gormModels.Region{
		RequiredLevel:    region.RequiredLevel,
		ImageUrl:         region.ImageUrl,
		Translations:     RegionTranslationsToGorm(region.Translations),
		RegionSlang:      RegionSlangsToGorm(region.RegionSlang),
		RegionTraditions: RegionTraditionsToGorm(region.RegionTraditions),
	}
}

func RegionTranslationsToGorm(translations []models.RegionTranslation) []gormModels.RegionTranslation {
	var res []gormModels.RegionTranslation

	for _, t := range translations {
		res = append(res, gormModels.RegionTranslation{
			RegionID:    t.RegionID,
			Language:    t.Language,
			Name:        t.Name,
			Description: t.Description,
		})
	}

	return res
}

func RegionSlangToGorm(sl models.RegionSlang) gormModels.RegionSlang {
	return gormModels.RegionSlang{
		RegionID:     sl.RegionID,
		Translations: RegionSlangTranslationsToGorm(sl.Translations),
	}
}

func RegionSlangsToGorm(sl []models.RegionSlang) []gormModels.RegionSlang {
	var res []gormModels.RegionSlang

	for _, s := range sl {
		res = append(res, gormModels.RegionSlang{
			RegionID:     s.RegionID,
			Translations: RegionSlangTranslationsToGorm(s.Translations),
		})
	}

	return res
}

func RegionSlangTranslationsToGorm(tr []models.RegionSlangTranslation) []gormModels.RegionSlangTranslation {
	var res []gormModels.RegionSlangTranslation

	for _, t := range tr {
		res = append(res, gormModels.RegionSlangTranslation{
			RegionSlangID: t.RegionSlangID,
			Language:      t.Language,
			Word:          t.Word,
			Description:   t.Description,
			PronounceURL:  t.PronounceURL,
		})
	}

	return res
}
func RegionSlangTranslationToGorm(t models.RegionSlangTranslation) gormModels.RegionSlangTranslation {
	return gormModels.RegionSlangTranslation{
		RegionSlangID: t.RegionSlangID,
		Language:      t.Language,
		Word:          t.Word,
		Description:   t.Description,
		PronounceURL:  t.PronounceURL,
	}
}
func RegionTraditionsToGorm(tr []models.RegionTraditions) []gormModels.RegionTraditions {
	var res []gormModels.RegionTraditions

	for _, t := range tr {
		res = append(res, gormModels.RegionTraditions{
			RegionID:     t.RegionID,
			Translations: RegionTraditionsTranslationsToGorm(t.Translations),
		})
	}

	return res
}
func RegionTraditionToGorm(tr models.RegionTraditions) gormModels.RegionTraditions {
	return gormModels.RegionTraditions{
		RegionID:     tr.RegionID,
		Translations: RegionTraditionsTranslationsToGorm(tr.Translations),
	}
}
func RegionTraditionsTranslationsToGorm(tr []models.RegionTraditionsTranslation) []gormModels.RegionTraditionsTranslation {
	var res []gormModels.RegionTraditionsTranslation

	for _, t := range tr {
		res = append(res, gormModels.RegionTraditionsTranslation{
			RegionTraditionsID: t.RegionTraditionsID,
			Language:           t.Language,
			Name:               t.Name,
			Description:        t.Description,
		})
	}

	return res
}
func RegionTraditionTranslationToGorm(t models.RegionTraditionsTranslation) gormModels.RegionTraditionsTranslation {
	return gormModels.RegionTraditionsTranslation{
		RegionTraditionsID: t.RegionTraditionsID,
		Language:           t.Language,
		Name:               t.Name,
		Description:        t.Description,
	}
}
func GormRegionToDomain(region gormModels.Region) models.Region {
	return models.Region{
		ID:               region.ID,
		RequiredLevel:    region.RequiredLevel,
		ImageUrl:         region.ImageUrl,
		Translations:     GormRegionTranslationsToDomain(region.Translations),
		RegionSlang:      GormRegionSlangsToDomain(region.RegionSlang),
		RegionTraditions: GormRegionTraditionsToDomain(region.RegionTraditions),
	}
}

func GormRegionTranslationsToDomain(tr []gormModels.RegionTranslation) []models.RegionTranslation {
	var res []models.RegionTranslation

	for _, t := range tr {
		res = append(res, models.RegionTranslation{
			ID:          t.ID,
			RegionID:    t.RegionID,
			Language:    t.Language,
			Name:        t.Name,
			Description: t.Description,
		})
	}

	return res
}

func GormRegionSlangsToDomain(sl []gormModels.RegionSlang) []models.RegionSlang {
	var res []models.RegionSlang

	for _, s := range sl {
		res = append(res, models.RegionSlang{
			ID:           s.ID,
			RegionID:     s.RegionID,
			Translations: GormRegionSlangTranslationsToDomain(s.Translations),
		})
	}

	return res
}
func GormRegionSlangToDomain(sl gormModels.RegionSlang) models.RegionSlang {
	return models.RegionSlang{
		ID:           sl.ID,
		RegionID:     sl.RegionID,
		Translations: GormRegionSlangTranslationsToDomain(sl.Translations),
	}
}

func GormRegionSlangTranslationsToDomain(tr []gormModels.RegionSlangTranslation) []models.RegionSlangTranslation {
	var res []models.RegionSlangTranslation

	for _, t := range tr {
		res = append(res, models.RegionSlangTranslation{
			ID:            t.ID,
			RegionSlangID: t.RegionSlangID,
			Language:      t.Language,
			Word:          t.Word,
			Description:   t.Description,
			PronounceURL:  t.PronounceURL,
		})
	}
	return res
}
func GormRegionSlangTranslationToDomain(t gormModels.RegionSlangTranslation) models.RegionSlangTranslation {
	return models.RegionSlangTranslation{
		ID:            t.ID,
		RegionSlangID: t.RegionSlangID,
		Language:      t.Language,
		Word:          t.Word,
		Description:   t.Description,
		PronounceURL:  t.PronounceURL,
	}
}

func GormRegionTraditionsToDomain(tr []gormModels.RegionTraditions) []models.RegionTraditions {
	var res []models.RegionTraditions

	for _, t := range tr {
		res = append(res, models.RegionTraditions{
			ID:           t.ID,
			RegionID:     t.RegionID,
			Translations: GormRegionTraditionsTranslationsToDomain(t.Translations),
		})
	}

	return res
}
func GormRegionTraditionToDomain(t gormModels.RegionTraditions) models.RegionTraditions {
	return models.RegionTraditions{
		ID:           t.ID,
		RegionID:     t.RegionID,
		Translations: GormRegionTraditionsTranslationsToDomain(t.Translations),
	}
}

func GormRegionTraditionsTranslationsToDomain(tr []gormModels.RegionTraditionsTranslation) []models.RegionTraditionsTranslation {
	var res []models.RegionTraditionsTranslation

	for _, t := range tr {
		res = append(res, models.RegionTraditionsTranslation{
			ID:                 t.ID,
			RegionTraditionsID: t.RegionTraditionsID,
			Language:           t.Language,
			Name:               t.Name,
			Description:        t.Description,
		})
	}

	return res
}
func GormRegionTraditionTranslationToDomain(t gormModels.RegionTraditionsTranslation) models.RegionTraditionsTranslation {
	return models.RegionTraditionsTranslation{
		ID:                 t.ID,
		RegionTraditionsID: t.RegionTraditionsID,
		Language:           t.Language,
		Name:               t.Name,
		Description:        t.Description,
	}
}
func RegionTranslationToGorm(t models.RegionTranslation) gormModels.RegionTranslation {
	return gormModels.RegionTranslation{
		RegionID:    t.RegionID,
		Language:    t.Language,
		Name:        t.Name,
		Description: t.Description,
	}
}
func GormRegionTranslationToDomain(t gormModels.RegionTranslation) models.RegionTranslation {
	return models.RegionTranslation{
		ID:          t.ID,
		RegionID:    t.RegionID,
		Language:    t.Language,
		Name:        t.Name,
		Description: t.Description,
	}
}
