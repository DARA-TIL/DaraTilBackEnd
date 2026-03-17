package services

import (
	"context"
)

type Event struct {
	Name     string
	Entity   string
	UserID   string
	EntityID string
}

type EventHandler interface {
	Handle(ctx context.Context, event Event) error
}

type Listener struct {
	Handlers map[string]EventHandler
}

func NewListener() *Listener {
	return &Listener{
		Handlers: make(map[string]EventHandler),
	}
}
func (l *Listener) AddEvent(event string, handler EventHandler) error {
	l.Handlers[event] = handler
	return nil
}
