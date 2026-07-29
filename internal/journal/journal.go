package journal

import (
	"context"
	"errors"

	"github.com/Vardominator/oh-my-safety/internal/model"
)

var (
	ErrEventIDConflict   = errors.New("journal event id already exists with different content")
	ErrFindingNotFound   = errors.New("finding not found")
	ErrInvalidTransition = errors.New("invalid finding lifecycle transition")
)

type Record struct {
	Sequence int64       `json:"sequence"`
	Event    model.Event `json:"event"`
}

type Journal interface {
	Append(context.Context, model.Event) (Record, error)
	Read(context.Context, int64, int) ([]Record, error)
}

type FindingReader interface {
	CurrentFinding(context.Context, string) (model.Finding, error)
	ListFindings(context.Context, ...model.FindingState) ([]model.Finding, error)
}
