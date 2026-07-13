// Cloud Enumeration — Step 3
//
//  3. Cloud Enumeration (Cloud Enum) [Optional, --skip-cloud-enum]
package company_flow

import (
	"path/filepath"

	"github.com/vishnu303/chaathan/pkg/logger"
)

// ─────────────────────────────────────────────────────────────
// Step 3 — Cloud Enumeration (Cloud Enum)
// ─────────────────────────────────────────────────────────────

// stepCloudEnum enumerates cloud infrastructure (S3, GCS, Azure Blob, etc.)
// associated with the target keyword.
// Returns (cancelled, error).
func stepCloudEnum(c *Ctx) (bool, error) {
	c.Total++

	if !c.SkipCloudEnum {
		logger.StepHeader("Step 3: Cloud Enumeration (Cloud Enum)")
		cloudOut := filepath.Join(c.ResultDir, "cloud_enum")
		logger.SubStep("Running Cloud Enum for keyword: %s", c.Company)

		if err := c.Tb.RunCloudEnum(c.GoCtx, c.Company, cloudOut); err != nil {
			logger.Warning("Cloud Enum failed: %v", err)
			c.Failed++
			return c.cancelled(), err
		} else {
			logger.Success("Cloud enumeration complete — results: %s", cloudOut+".json")
			c.Completed++
		}
	} else {
		logger.StepHeader("Step 3: Skipping Cloud Enum (--skip-cloud-enum)")
		c.Completed++
	}

	return c.cancelled(), nil
}
