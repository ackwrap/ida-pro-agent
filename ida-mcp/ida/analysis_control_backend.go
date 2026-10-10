package ida

import "context"

// AnalysisControlBackend exposes only the statically typed queue mutation.
type AnalysisControlBackend interface {
	AnalysisPlan(context.Context, string, AnalysisPlanParams) (AnalysisPlanResult, error)
}
