package options

import (
	"fmt"
	"log"

	"github.com/dlclark/regexp2"
)

type Keyword struct {
	IP     []string
	Domain []string
	DSL    []queries
}

type queries struct {
	Raw    string
	Groups []query
	Expr   string
}

func NewDslSlice(input string) []queries {
	q := parseInput(input)
	if len(q.Groups) > 0 {
		return []queries{q}
	}
	return []queries{}
}

type query struct {
	Key   string
	Value string
}

var parsePat = regexp2.MustCompile(`(ip|domain|icon\.md5|icon\.mmh3|cert|title|body)\s{0,}=\s{0,}["']([^"'\n]+)["']`, regexp2.None)

func parseInput(input string) queries {
	ret := queries{Raw: input}
	m, err := parsePat.FindStringMatch(input)
	if err != nil {
		log.Println(err)
		return ret
	}

	index := 0
	ret.Expr, err = parsePat.ReplaceFunc(input, func(m regexp2.Match) string {
		defer func() { index += 1 }()
		return fmt.Sprintf("[%d]", index)
	}, -1, -1)

	for m != nil {
		if m.GroupCount() != 3 {
			continue
		}
		ret.Groups = append(ret.Groups, query{m.Groups()[1].String(), m.Groups()[2].String()})
		m, err = parsePat.FindNextMatch(m)
		if err != nil {
			break
		}
	}

	return ret
}
