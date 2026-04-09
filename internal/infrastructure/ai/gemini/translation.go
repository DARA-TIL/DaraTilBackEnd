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

func (ai *AiGemini) WordExplain(ctx context.Context, word models.WordExplain) (*models.WordExplainResult, error) {
	textQuery := fmt.Sprintf(
		`You are a language-learning assistant.

				Your task is to explain the meaning of a selected word based on the context block where it appears.
				
				Input:
				- word: "%s"
				- block: "%s"
				- lang: "%s"
				
				Instructions:
				1. Analyze the selected word only in the context of the provided block.
				2. Detect its meaning in this specific context.
				3. Return a short, clear explanation suitable for a learner.
				4. If the word has multiple meanings, choose only the meaning that matches the block.
				5. Return the answer in the language specified by "lang".
				6. Keep the explanation concise and educational.
				7. Also provide part of speech, translation, and one simple example sentence.
				8. If the word is unknown, unclear, or the context is insufficient, say so briefly.`,
		word.Word, word.Block, word.Lang,
	)
	answerConfig := &genai.GenerateContentConfig{
		ResponseMIMEType: "application/json",
		ResponseJsonSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"result": map[string]any{
					"type":        "string",
					"description": "The name in kazakh language",
				},
				"context": map[string]any{
					"type":        "string",
					"description": "example or context where this word can be used",
				},
			},
		},
	}
	res, err := ai.client.Models.GenerateContent(ctx, "gemini-2.5-flash", genai.Text(textQuery), answerConfig)
	if err != nil {
		return nil, err
	}
	var exp models.WordExplainResult
	err = json.Unmarshal([]byte(res.Text()), &exp)
	if err != nil {
		return nil, err
	}
	return &exp, nil
}
func (ai *AiGemini) Translate(ctx context.Context, query string) (*models.TranslationObj, error) {
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
