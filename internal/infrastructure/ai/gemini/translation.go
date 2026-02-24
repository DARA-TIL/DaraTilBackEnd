package gemini

import (
	"DaraTilBackendV2/internal/config"
	"DaraTilBackendV2/internal/domain/models"
	"context"
	"encoding/json"
	"fmt"
	"log"

	"google.golang.org/genai"
)

type AiGemini struct {
	client *genai.Client
}

func NewGeminiAI(cfg *config.Config) *AiGemini {
	client, err := genai.NewClient(context.Background(), &genai.ClientConfig{
		APIKey:  cfg.Gemini.GeminiApiKey,
		Backend: genai.BackendGeminiAPI,
	})
	if err != nil {
		log.Fatal(err)
	}
	return &AiGemini{client: client}
}

func (ai AiGemini) Translate(ctx context.Context, query string) (*models.TranslationObj, error) {
	textQuery := fmt.Sprintf(
		"Can you translate the following fields in Russian and Kazakh and also explain it, and map " +
			"it in a JSON format without any backticks or additional symbols? For Kazakh" +
			" and Russian, use Cyrillic. Return only the JSON " +
			"format for the translations, without any additional text.If one of the fields is empty return it with blank\n\n" +
			query)

	answerConfig := &genai.GenerateContentConfig{
		ResponseMIMEType: "application/json",
		ResponseJsonSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"nameKz": map[string]any{
					"type":        "string",
					"description": "The name in kazakh language",
				},
				"nameRu": map[string]any{
					"type":        "string",
					"description": "The name in russian language",
				},
				"nameEn": map[string]any{
					"type":        "string",
					"description": "The name in english language",
				},
				"contentKz": map[string]any{
					"type":        "string",
					"description": "The content in kazakh language",
				},
				"contentRu": map[string]any{
					"type":        "string",
					"description": "The content in russian language",
				},
				"contentEn": map[string]any{
					"type":        "string",
					"description": "The content in english language",
				},
				"explanationKz": map[string]any{
					"type":        "string",
					"description": "The explanation of content in kazakh language",
				},
				"explanationRu": map[string]any{
					"type":        "string",
					"description": "The explanation of content in russian language",
				},
				"explanationEn": map[string]any{
					"type":        "string",
					"description": "The explanation of content in english language",
				},
			},
		},
	}
	res, err := ai.client.Models.GenerateContent(
		ctx,
		"gemini-2.5-flash",
		genai.Text(textQuery),
		answerConfig,
	)
	if err != nil {
		return nil, err
	}
	var translations models.TranslationObj

	err = json.Unmarshal([]byte(res.Text()), &translations)
	return &translations, err
}
