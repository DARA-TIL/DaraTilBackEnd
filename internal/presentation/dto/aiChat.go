package dto

type CreateAIChatRequest struct {
	Name string `json:"name" binding:"required"`
}

type UpdateAIChatRequest struct {
	Name string `json:"name" binding:"required"`
}

type AIChatResponse struct {
	ID       uint                    `json:"id"`
	Name     string                  `json:"name"`
	UserID   uint                    `json:"userId"`
	Messages []AIChatMessageResponse `json:"messages,omitempty"`
}

type CreateAIChatMessageRequest struct {
	ChatID     uint   `json:"chatId" binding:"required"`
	Message    string `json:"message" binding:"required"`
	SenderType string `json:"senderType" binding:"required"`
}

type AIChatMessageResponse struct {
	ID         uint   `json:"id"`
	ChatID     uint   `json:"chatId"`
	Message    string `json:"message"`
	SenderType string `json:"senderType"`
	UserID     *uint  `json:"userId,omitempty"`
}
