package utils

import (
	"DaraTilBackEnd/backend/internal/config"
	"fmt"
	"net/smtp"
)

var (
	smtpHost = "smtp.gmail.com"
	smtpPort = "587"
)

func SendEmail(toEmail, fromEmail, subject, text string, cfg config.Config) error {
	auth := cfg.SmtpAuth()
	body := fmt.Sprintf("Subject: %s\n\n%s\n\nFrom: %s", subject, text, fromEmail)

	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, fromEmail, []string{toEmail}, []byte(body))
	if err != nil {
		return err
	}
	return nil
}
