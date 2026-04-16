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

func (ai *AiGemini) WordExplain(ctx context.Context, word models.WordRequest) (*models.WordExplainResult, error) {
	textQuery := fmt.Sprintf(
		`You are a language-learning assistant.

				Your task is to explain the meaning of a selected word only in the context of the provided block and return the result in three languages: Kazakh, Russian, and English.
				
				Input:
				- word: "%s"
				- block: "%s"
				
				Instructions:
				1. Analyze the selected word only in the context of the provided block.
				2. Determine the meaning of the word in this specific context.
				3. Return a JSON object only.
				4. Provide:
				   - "wordTranslations": direct translations of the selected word into Kazakh, Russian, and English.
				   - "wordExplainingTranslations": short learner-friendly explanations of the word's meaning in this context in Kazakh, Russian, and English.
				5. Keep each explanation concise, clear, and educational.
				6. If the word is unknown, unclear, or the context is insufficient, still return valid JSON and briefly state that the meaning is unclear in each explanation field.
				7. Do not include any extra fields, comments, markdown, or formatting outside the JSON object.
				
				Important:
				- Choose only the meaning that matches the given block.
				- Do not list multiple meanings.
				- Keep the explanations short and simple for language learners.`,
		word.Word, word.Block,
	)
	answerConfig := &genai.GenerateContentConfig{
		ResponseMIMEType: "application/json",
		ResponseJsonSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"wordTranslations": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"KZ": map[string]any{
							"type":        "string",
							"description": "Translation of the word in Kazakh",
						},
						"RU": map[string]any{
							"type":        "string",
							"description": "Translation of the word in Russian",
						},
						"EN": map[string]any{
							"type":        "string",
							"description": "Translation of the word in English",
						},
					},
					"required": []string{"KZ", "RU", "EN"},
				},
				"wordExplainingTranslations": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"KZ": map[string]any{
							"type":        "string",
							"description": "Explanation or usage context in Kazakh",
						},
						"RU": map[string]any{
							"type":        "string",
							"description": "Explanation or usage context in Russian",
						},
						"EN": map[string]any{
							"type":        "string",
							"description": "Explanation or usage context in English",
						},
					},
					"required": []string{"KZ", "RU", "EN"},
				},
			},
			"required": []string{"wordTranslations", "wordExplainingTranslations"},
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
