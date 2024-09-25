package utils

type StringSet map[string]struct{}

func NewStringSet(a ...string) StringSet {
	s := StringSet{}
	s.Add(a...)
	return s
}

func NewStringSetByArray(a []string) StringSet {
	s := StringSet{}
	if a != nil {
		s.Add(a...)
	}
	return s
}

func (this StringSet) AddAll(n []string) {
	this.Add(n...)
}

func (this StringSet) Add(n ...string) {
	for _, p := range n {
		this[p] = struct{}{}
	}
}

func (this StringSet) Contains(n string) bool {
	_, ok := this[n]
	return ok
}

func (this StringSet) AsArray() []string {
	a := []string{}
	for n := range this {
		a = append(a, n)
	}
	return a
}
