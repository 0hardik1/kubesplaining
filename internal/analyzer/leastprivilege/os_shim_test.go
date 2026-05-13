package leastprivilege

import "os"

// osCreate is a tiny indirection so the test helpers can pretend the create surface is
// an interface (useful when we later swap in gzip writers for compressed-fixture
// scenarios). For now it's just os.Create.
func osCreate(path string) (*os.File, error) {
	return os.Create(path)
}
