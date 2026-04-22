package dictionaryUC

import (
	"DaraTilBackendV2/internal/application/services"
	"DaraTilBackendV2/internal/application/utils"
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
	"errors"
	"fmt"
)

type AddFavoriteUC struct {
	dictionaryRepo repo.DictionaryRepo
	explainer      repo.WordExplainer
	publisher      services.Publisher
}

func NewAddFavoriteUC(explainer repo.WordExplainer, publisher services.Publisher, dictionaryRepo repo.DictionaryRepo) *AddFavoriteUC {
	return &AddFavoriteUC{
		dictionaryRepo: dictionaryRepo,
		explainer:      explainer,
		publisher:      publisher,
	}
}

func (uc *AddFavoriteUC) AddWithID(ctx context.Context, wordID, userID uint) error {
	return uc.dictionaryRepo.AddToFavorite(ctx, wordID, userID)

}
func (uc *AddFavoriteUC) Add(ctx context.Context, req models.WordRequest, userID uint) error {
	w, err := uc.dictionaryRepo.GetExactWord(ctx, req.Word, req.Block)
	if err != nil {
		fmt.Println(err)
		if !errors.Is(err, errs.ErrNotFound) {
			return err
		}
		word, err := utils.ExplainAndCreateWord(ctx, req, uc.explainer, uc.dictionaryRepo)
		if err != nil {
			return err
		}
		err = uc.dictionaryRepo.AddToFavorite(ctx, word.ID, userID)
		if err != nil {
			return err
		}
		uc.publisher.Publish(ctx, services.Event{
			Action: models.Word_Learned,
			UserID: userID,
		})
		return nil
	}
	err = uc.dictionaryRepo.AddToFavorite(ctx, w.ID, userID)
	if err != nil {
		return err
	}
	uc.publisher.Publish(ctx, services.Event{
		Action: models.Word_Learned,
		UserID: userID,
	})
	return nil
}
