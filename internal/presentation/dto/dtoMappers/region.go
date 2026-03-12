package dtoMappers

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/presentation/dto"
)

const (
	RegionLocked    = "locked"
	RegionAvailable = "available"
)

func RegionToDTO(region models.Region) dto.Region {
	return dto.Region{
		ID:               region.ID,
		RequiredLevel:    region.RequiredLevel,
		ImageUrl:         region.ImageUrl,
		RegionStatus:     RegionAvailable,
		Translations:     RegionTranslationsToDTO(region.Translations),
		RegionSlang:      RegionSlangsToDTO(region.RegionSlang),
		RegionTraditions: RegionTraditionsToDTO(region.RegionTraditions),
	}
}

func RegionsToDTO(regions []models.Region) []dto.Region {
	var res []dto.Region
	for _, r := range regions {
		res = append(res, RegionToDTO(r))
	}
	return res
}
func CheckRegionsAvailability(regions []dto.Region, userLevel int) {
	for i := range regions {
		if regions[i].RequiredLevel > userLevel {
			regions[i].RegionStatus = RegionLocked
		}
	}
}
func RegionTranslationsToDTO(tr []models.RegionTranslation) []dto.RegionTranslation {
	var res []dto.RegionTranslation

	for _, t := range tr {
		res = append(res, dto.RegionTranslation{
			ID:          t.ID,
			RegionID:    t.RegionID,
			Language:    t.Language,
			Name:        t.Name,
			Description: t.Description,
		})
	}

	return res
}
func RegionTranslationToDomain(t dto.RegionTranslation) models.RegionTranslation {
	return models.RegionTranslation{
		ID:          t.ID,
		RegionID:    t.RegionID,
		Language:    t.Language,
		Name:        t.Name,
		Description: t.Description,
	}
}
func RegionTranslationToDTO(t models.RegionTranslation) dto.RegionTranslation {
	return dto.RegionTranslation{
		ID:          t.ID,
		RegionID:    t.RegionID,
		Language:    t.Language,
		Name:        t.Name,
		Description: t.Description,
	}
}
func RegionSlangsToDTO(sl []models.RegionSlang) []dto.RegionSlang {
	var res []dto.RegionSlang

	for _, s := range sl {
		res = append(res, dto.RegionSlang{
			ID:           s.ID,
			RegionID:     s.RegionID,
			Translations: RegionSlangTranslationsToDTO(s.Translations),
		})
	}

	return res
}

func RegionSlangToDTO(sl models.RegionSlang) dto.RegionSlang {
	return dto.RegionSlang{
		ID:           sl.ID,
		RegionID:     sl.RegionID,
		Translations: RegionSlangTranslationsToDTO(sl.Translations),
	}
}

func RegionSlangTranslationsToDTO(tr []models.RegionSlangTranslation) []dto.RegionSlangTranslation {
	var res []dto.RegionSlangTranslation

	for _, t := range tr {
		res = append(res, dto.RegionSlangTranslation{
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

func RegionTraditionsToDTO(tr []models.RegionTraditions) []dto.RegionTraditions {
	var res []dto.RegionTraditions

	for _, t := range tr {
		res = append(res, dto.RegionTraditions{
			ID:           t.ID,
			RegionID:     t.RegionID,
			Translations: RegionTraditionsTranslationsToDTO(t.Translations),
		})
	}

	return res
}

func RegionTraditionToDTO(tr models.RegionTraditions) dto.RegionTraditions {
	return dto.RegionTraditions{
		ID:           tr.ID,
		RegionID:     tr.RegionID,
		Translations: RegionTraditionsTranslationsToDTO(tr.Translations),
	}
}

func RegionTraditionsTranslationsToDTO(tr []models.RegionTraditionsTranslation) []dto.RegionTraditionsTranslation {
	var res []dto.RegionTraditionsTranslation

	for _, t := range tr {
		res = append(res, dto.RegionTraditionsTranslation{
			ID:                 t.ID,
			RegionTraditionsID: t.RegionTraditionsID,
			Language:           t.Language,
			Name:               t.Name,
			Description:        t.Description,
		})
	}

	return res
}

func RegionToDomain(region dto.Region) models.Region {
	return models.Region{
		ID:               region.ID,
		RequiredLevel:    region.RequiredLevel,
		ImageUrl:         region.ImageUrl,
		Translations:     RegionTranslationsToDomain(region.Translations),
		RegionSlang:      RegionSlangsToDomain(region.RegionSlang),
		RegionTraditions: RegionTraditionsToDomain(region.RegionTraditions),
	}
}

func RegionsToDomain(regions []dto.Region) []models.Region {
	var res []models.Region
	for _, r := range regions {
		res = append(res, RegionToDomain(r))
	}
	return res
}

func RegionTranslationsToDomain(tr []dto.RegionTranslation) []models.RegionTranslation {
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

func RegionSlangsToDomain(sl []dto.RegionSlang) []models.RegionSlang {
	var res []models.RegionSlang

	for _, s := range sl {
		res = append(res, models.RegionSlang{
			ID:           s.ID,
			RegionID:     s.RegionID,
			Translations: RegionSlangTranslationsToDomain(s.Translations),
		})
	}

	return res
}

func RegionSlangToDomain(sl dto.RegionSlang) models.RegionSlang {
	return models.RegionSlang{
		ID:           sl.ID,
		RegionID:     sl.RegionID,
		Translations: RegionSlangTranslationsToDomain(sl.Translations),
	}
}

func RegionSlangTranslationsToDomain(tr []dto.RegionSlangTranslation) []models.RegionSlangTranslation {
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

func RegionTraditionsToDomain(tr []dto.RegionTraditions) []models.RegionTraditions {
	var res []models.RegionTraditions

	for _, t := range tr {
		res = append(res, models.RegionTraditions{
			ID:           t.ID,
			RegionID:     t.RegionID,
			Translations: RegionTraditionsTranslationsToDomain(t.Translations),
		})
	}

	return res
}

func RegionTraditionToDomain(tr dto.RegionTraditions) models.RegionTraditions {
	return models.RegionTraditions{
		ID:           tr.ID,
		RegionID:     tr.RegionID,
		Translations: RegionTraditionsTranslationsToDomain(tr.Translations),
	}
}

func RegionTraditionsTranslationsToDomain(tr []dto.RegionTraditionsTranslation) []models.RegionTraditionsTranslation {
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
func RegionSlangTranslationToDomain(t dto.RegionSlangTranslation) models.RegionSlangTranslation {
	return models.RegionSlangTranslation{
		ID:            t.ID,
		RegionSlangID: t.RegionSlangID,
		Language:      t.Language,
		Word:          t.Word,
		Description:   t.Description,
		PronounceURL:  t.PronounceURL,
	}
}
func RegionSlangTranslationToDTO(t models.RegionSlangTranslation) dto.RegionSlangTranslation {
	return dto.RegionSlangTranslation{
		ID:            t.ID,
		RegionSlangID: t.RegionSlangID,
		Language:      t.Language,
		Word:          t.Word,
		Description:   t.Description,
		PronounceURL:  t.PronounceURL,
	}
}
func RegionTraditionTranslationToDomain(t dto.RegionTraditionsTranslation) models.RegionTraditionsTranslation {
	return models.RegionTraditionsTranslation{
		ID:                 t.ID,
		RegionTraditionsID: t.RegionTraditionsID,
		Language:           t.Language,
		Name:               t.Name,
		Description:        t.Description,
	}
}
func RegionTraditionTranslationToDTO(t models.RegionTraditionsTranslation) dto.RegionTraditionsTranslation {
	return dto.RegionTraditionsTranslation{
		ID:                 t.ID,
		RegionTraditionsID: t.RegionTraditionsID,
		Language:           t.Language,
		Name:               t.Name,
		Description:        t.Description,
	}
}
