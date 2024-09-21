package sources

type Agent interface {
	Query(*Session, string) (chan Result, error)
	Name() string
}
