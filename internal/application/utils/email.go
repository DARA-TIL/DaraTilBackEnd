package utils

import (
	"DaraTilBackendV2/internal/config"
	"fmt"

	"net/smtp"
)

var (
	smtpHost = "smtp.gmail.com"
	smtpPort = "587"
)

func SmtpAuth(cfg config.Config) smtp.Auth {
	smtpHost := "smtp.gmail.com"
	username := cfg.Smtp.SmtpUser
	password := cfg.Smtp.SmtpPass
	auth := smtp.PlainAuth("", username, password, smtpHost)
	return auth
}

func SendEmailSMTP(toEmail, fromEmail, subject, text string, cfg config.Config) error {
	auth := SmtpAuth(cfg)
	body := fmt.Sprintf("Subject: %s\n\n%s\n\nFrom: %s", subject, text, fromEmail)

	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, fromEmail, []string{toEmail}, []byte(body))
	if err != nil {
		return err
	}
	return nil
}
