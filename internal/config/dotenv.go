package config

import (
	"errors"
	"fmt"
	"io/fs"

	"github.com/joho/godotenv"
)

// DotEnvFile is the conventional dotenv path, relative to the working directory.
const DotEnvFile = ".env"

// DotEnvError reports that a dotenv file could not be parsed.
//
// It names the file and nothing else. The underlying parser error is discarded on purpose
// — see LoadDotEnv.
type DotEnvError struct {
	Path string
}

func (e *DotEnvError) Error() string {
	return fmt.Sprintf(
		"%s is malformed and was not loaded (contents withheld: the file holds secrets).\n"+
			"Look for a line missing '=', or a value containing a line break — pasting a key "+
			"with a trailing newline is the usual cause.",
		e.Path)
}

// LoadDotEnv loads path into the environment if it exists.
//
// A missing file is not an error: production has no .env by design and takes its
// configuration from the real environment. Variables already set always win, because
// godotenv.Load does not overwrite them — never switch this to Overload, or a stale local
// .env would silently override deployed configuration.
//
// A parse error is deliberately NOT wrapped. godotenv embeds the unparsed remainder of the
// file in its error text, so wrapping it prints every key after the offending line to
// stderr — a typo in one credential discloses all the others. The caller only ever needs
// to know that the file is malformed, never what it contains (spec §4).
func LoadDotEnv(path string) error {
	err := godotenv.Load(path)
	if err == nil || errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return &DotEnvError{Path: path}
}
