package sshd

import (
	"errors"
	"strings"
)

// Tokenize implements POSIX-style quoting without shell evaluation. Operators
// and expansion syntax are rejected unquoted before the guest delimiter `--`
// and are literal after it; quoted/escaped bytes are always literal.
func Tokenize(line string) ([]string, error) {
	if len(line) > 16384 {
		return nil, errors.New("command too long")
	}
	var tokens []string
	var word strings.Builder
	quote := byte(0)
	active := false
	literal := false
	flush := func() {
		if active {
			tokens = append(tokens, word.String())
			word.Reset()
			active = false
			if !literal && tokens[len(tokens)-1] == "--" {
				literal = true
			}
		}
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == 0 || c == '\n' || c == '\r' {
			return nil, errors.New("command must be one line")
		}
		if quote == '\'' {
			if c == '\'' {
				quote = 0
			} else {
				word.WriteByte(c)
			}
			continue
		}
		if c == '\\' {
			if i+1 >= len(line) {
				return nil, errors.New("trailing escape")
			}
			next := line[i+1]
			if quote == '"' && next != '"' && next != '\\' && next != '$' && next != '`' {
				word.WriteByte(c)
				active = true
				continue
			}
			if next == 0 || next == '\n' || next == '\r' {
				return nil, errors.New("command must be one line")
			}
			i++
			word.WriteByte(next)
			active = true
			continue
		}
		if quote == '"' {
			if c == '"' {
				quote = 0
			} else {
				word.WriteByte(c)
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
			active = true
		case ' ', '\t':
			flush()
		case '|', '&', ';', '<', '>', '(', ')', '$', '`':
			if !literal {
				return nil, errors.New("shell operators and expansion are not supported before --; when calling through ssh, quote the whole command: ssh silo \"exec VM -- CMD 'ARG'\"")
			}
			word.WriteByte(c)
			active = true
		default:
			word.WriteByte(c)
			active = true
		}
	}
	if quote != 0 {
		return nil, errors.New("unterminated quote")
	}
	flush()
	return tokens, nil
}
