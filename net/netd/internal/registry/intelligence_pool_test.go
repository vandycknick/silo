package registry

import "testing"

func TestIntelligencePoolSharesEquivalentFeedSnapshots(t *testing.T) {
	pool := NewIntelligencePool(nil)
	firstCatalog, err := NewCatalog([]string{"npm", "pypi"})
	if err != nil {
		t.Fatal(err)
	}
	secondCatalog, err := NewCatalog([]string{"pypi", "npm"})
	if err != nil {
		t.Fatal(err)
	}
	first, err := pool.Get("https://intelligence.example.com/base", firstCatalog)
	if err != nil {
		t.Fatal(err)
	}
	second, err := pool.Get("https://intelligence.example.com/base", secondCatalog)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("equivalent feed configuration did not share an intelligence snapshot")
	}
}

func TestIntelligencePoolSeparatesDifferentEcosystemSets(t *testing.T) {
	pool := NewIntelligencePool(nil)
	npmCatalog, err := NewCatalog([]string{"npm"})
	if err != nil {
		t.Fatal(err)
	}
	pypiCatalog, err := NewCatalog([]string{"pypi"})
	if err != nil {
		t.Fatal(err)
	}
	npm, err := pool.Get("https://intelligence.example.com/base", npmCatalog)
	if err != nil {
		t.Fatal(err)
	}
	pypi, err := pool.Get("https://intelligence.example.com/base", pypiCatalog)
	if err != nil {
		t.Fatal(err)
	}
	if npm == pypi {
		t.Fatal("different ecosystem sets shared an intelligence snapshot")
	}
}
