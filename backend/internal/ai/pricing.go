package ai

// Prices in USD per million tokens (Anthropic API list prices, 2026-10).
// Cache writes (5-minute TTL) cost 1.25x input, cache reads 0.1x input; the
// Message Batches API halves everything.
var prices = map[string]struct{ in, out float64 }{
	"claude-sonnet-5-5": {2.00, 10.00},
	"claude-opus-5-5":   {4.00, 20.00},
	"claude-haiku-5-5":  {0.10, 0.50},
}

// Cost estimates what a call cost. Unknown models are priced like Opus so a
// budget is never underestimated.
func Cost(model string, u Usage, batch bool) float64 {
	p, ok := prices[model]
	if !ok {
		p = prices["claude-opus-5-5"]
	}
	c := (float64(u.InputTokens)*p.in +
		float64(u.CacheCreationTokens)*p.in*1.25 +
		float64(u.CacheReadTokens)*p.in*0.1 +
		float64(u.OutputTokens)*p.out) / 1e6
	if batch {
		c /= 2
	}
	return c
}
