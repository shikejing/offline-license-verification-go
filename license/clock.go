package license

import "time"

// Clock abstracts time source so verification semantics can be tested
// deterministically without touching the system clock.
type Clock interface {
	Now() time.Time
}

// realClock uses the system wall clock.
type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }
