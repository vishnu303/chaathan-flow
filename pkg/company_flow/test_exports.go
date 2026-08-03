package company_flow

// Exported wrappers for testing purposes only.

// CountFindingsForStep exposes the unexported countFindingsForStep to tests.
func CountFindingsForStep(c *Ctx, stepName string) int {
	return countFindingsForStep(c, stepName)
}
