package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/rs/zerolog"
)

// OutputMode controls how results are printed.
type OutputMode int

const (
	OutputHuman OutputMode = iota
	OutputJSON
	OutputQuiet
)

// Printer handles structured output for every command.
type Printer struct {
	Mode   OutputMode
	Writer io.Writer
	Logger zerolog.Logger
}

// NewPrinter creates a Printer from the global flags.
func NewPrinter(jsonFlag, quietFlag bool) *Printer {
	mode := OutputHuman
	if jsonFlag {
		mode = OutputJSON
	} else if quietFlag {
		mode = OutputQuiet
	}
	return &Printer{
		Mode:   mode,
		Writer: os.Stdout,
		Logger: zerolog.New(os.Stderr).With().Timestamp().Logger(),
	}
}

// JSON writes v as indented JSON to the writer.
func (p *Printer) JSON(v any) error {
	enc := json.NewEncoder(p.Writer)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// Human writes a formatted human-readable line.
func (p *Printer) Human(format string, args ...any) {
	if p.Mode == OutputQuiet {
		return
	}
	fmt.Fprintf(p.Writer, format+"\n", args...)
}

// Error logs an error via zerolog.
func (p *Printer) Error(err error, msg string) {
	p.Logger.Error().Err(err).Msg(msg)
}
