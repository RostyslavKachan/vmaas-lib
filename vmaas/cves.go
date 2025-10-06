package vmaas

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/redhatinsights/vmaas-lib/vmaas/utils"
)

type CveDetails map[string]CveDetail

type Cves struct {
	Cves       CveDetails `json:"cve_list"`
	LastChange time.Time  `json:"last_change" example:"2024-11-20T12:36:49.640592Z"`
	utils.Pagination
}

// buildCSAFCVESet creates a set of CVE IDs that have CSAF erratum
// This is done once to avoid iterating through CSAF structures for each CVE
// We use CSAFCVEProduct2Erratum which contains only CVEs with erratum (Fixed)
func buildCSAFCVESet(c *Cache) map[int]bool {
	csafCVESet := make(map[int]bool)

	// Iterate through CSAFCVEProduct2Erratum map once
	// This map contains only CVEs that have an associated erratum
	for csafCVEProduct := range c.CSAFCVEProduct2Erratum {
		csafCVESet[int(csafCVEProduct.CVEID)] = true
	}
	utils.LogInfo("We are here")
	return csafCVESet
}

// buildCVEName2IDMap creates a reverse map from CVE name to CVE ID
// This allows O(1) lookup instead of O(N) iteration through CveNames
func buildCVEName2IDMap(c *Cache) map[string]int {
	cveName2ID := make(map[string]int, len(c.CveNames))

	for id, name := range c.CveNames {
		cveName2ID[name] = id
	}

	return cveName2ID
}

func filterInputCves(c *Cache, cves []string, req *CvesRequest) []string {
	isDuplicate := make(map[string]bool, len(cves))
	filteredIDs := make([]string, 0, len(cves))

	// Build CSAF CVE set and CVE name->ID map once before the loop (optimization)
	var csafCVESet map[int]bool
	var cveName2ID map[string]int
	if req.AreErrataAssociated {
		csafCVESet = buildCSAFCVESet(c)
		cveName2ID = buildCVEName2IDMap(c)
	}

	for _, cve := range cves {
		if cve == "" || isDuplicate[cve] {
			continue
		}
		cveDetail, found := c.CveDetail[cve]
		if !found {
			continue
		}
		if req.RHOnly && cveDetail.Source != "Red Hat" {
			continue
		}

		if req.AreErrataAssociated {
			hasErrata := len(cveDetail.ErratumIDs) > 0

			// Check if CVE exists in CSAF using pre-built maps (O(1) lookup)
			cveID, exists := cveName2ID[cve]
			hasCSAF := exists && csafCVESet[cveID]

			utils.LogInfo("🔍 [FILTER] CVE:", cve)
			utils.LogInfo("🔍 [FILTER] Has Errata:", fmt.Sprintf("%t", hasErrata))
			utils.LogInfo("🔍 [FILTER] Has CSAF:", fmt.Sprintf("%t", hasCSAF))

			if !hasErrata && !hasCSAF {
				utils.LogInfo("🔍 [FILTER] Excluding CVE (no errata, no CSAF):", cve)
				continue
			}
			utils.LogInfo("🔍 [FILTER] Including CVE (has errata or CSAF):", cve)
		}

		if req.ModifiedSince != nil {
			if cveDetail.ModifiedDate == nil || cveDetail.ModifiedDate.Before(*req.ModifiedSince) {
				continue
			}
		}
		if req.PublishedSince != nil {
			if cveDetail.PublishedDate == nil || cveDetail.PublishedDate.Before(*req.PublishedSince) {
				continue
			}
		}

		filteredIDs = append(filteredIDs, cve)
		isDuplicate[cve] = true
	}
	return filteredIDs
}

func (c *Cache) getCveDetails(cves []string) CveDetails {
	cveDetails := make(CveDetails, len(cves))
	for _, cve := range cves {
		cveDetail := c.CveDetail[cve]
		cveDetail.Name = cve
		cveDetail.Errata = c.erratumIDs2Names(cveDetail.ErratumIDs)
		binPackages, sourcePackages := c.packageIDs2Nevras(cveDetail.PkgIDs)
		cveDetail.Packages = binPackages
		cveDetail.SourcePackages = sourcePackages
		if cveDetail.CWEs == nil {
			cveDetail.CWEs = []string{}
		}
		cveDetails[cve] = cveDetail
	}
	return cveDetails
}

// getCSAFInfoForCVE returns CSAF information for a specific CVE
func getCSAFInfoForCVE(c *Cache, cve string) map[string]interface{} {
	csafInfo := make(map[string]interface{})

	// Find CVE ID
	cveID := -1
	for id, name := range c.CveNames {
		if name == cve {
			cveID = id
			break
		}
	}

	if cveID == -1 {
		csafInfo["found"] = false
		csafInfo["message"] = "CVE not found in CSAF data"
		return csafInfo
	}

	csafInfo["found"] = true
	csafInfo["cve_id"] = cveID

	// Check CSAF data for this CVE
	csafProducts := make([]map[string]interface{}, 0)

	// Iterate through CSAF data
	for variant, cpeData := range c.CSAFCVEs {
		for _, productData := range cpeData {
			for productID, csafCves := range productData {
				// Check if this CVE is in Fixed or Unfixed
				fixed := false
				unfixed := false

				for _, fixedCVE := range csafCves.Fixed {
					if int(fixedCVE) == cveID {
						fixed = true
						break
					}
				}

				for _, unfixedCVE := range csafCves.Unfixed {
					if int(unfixedCVE) == cveID {
						unfixed = true
						break
					}
				}

				if fixed || unfixed {
					product := c.CSAFProductID2Product[productID]
					productInfo := map[string]interface{}{
						"product_id":      int(productID),
						"variant":         variant,
						"cpe_id":          int(product.CpeID),
						"package_name_id": int(product.PackageNameID),
						"package_id":      int(product.PackageID),
						"module_stream":   product.ModuleStream,
						"fixed":           fixed,
						"unfixed":         unfixed,
					}
					csafProducts = append(csafProducts, productInfo)
				}
			}
		}
	}

	csafInfo["products"] = csafProducts
	csafInfo["total_products"] = len(csafProducts)

	return csafInfo
}

// logCvesRequestFields logs all fields from CvesRequest in a safe way
func logCvesRequestFields(req *CvesRequest) {
	// Convert time fields to strings safely
	var publishedSinceStr, modifiedSinceStr string
	if req.PublishedSince != nil {
		publishedSinceStr = req.PublishedSince.Format(time.RFC3339)
	} else {
		publishedSinceStr = "<nil>"
	}
	if req.ModifiedSince != nil {
		modifiedSinceStr = req.ModifiedSince.Format(time.RFC3339)
	} else {
		modifiedSinceStr = "<nil>"
	}

	// Simple log with basic info
	utils.LogInfo("🔍 [CVE-REQUEST] START - CvesRequest received")
	utils.LogInfo("📋 CVE Count:", fmt.Sprintf("%d", len(req.Cves)))
	utils.LogInfo("📋 CVE List:", strings.Join(req.Cves, ","))
	utils.LogInfo("📦 Errata Associated:", fmt.Sprintf("%t", req.AreErrataAssociated))
	utils.LogInfo("🔴 RH Only:", fmt.Sprintf("%t", req.RHOnly))
	utils.LogInfo("🌐 Third Party:", fmt.Sprintf("%t", req.ThirdParty))
	utils.LogInfo("📅 Published Since:", publishedSinceStr)
	utils.LogInfo("🔄 Modified Since:", modifiedSinceStr)
	utils.LogInfo("📄 Page Number:", fmt.Sprintf("%d", req.PageNumber))
	utils.LogInfo("📊 Page Size:", fmt.Sprintf("%d", req.PageSize))
	utils.LogInfo("№№№№№№№№№№№№№№№№№№№№№", "END OF REQUEST FIELDS")
}

func (req *CvesRequest) cves(c *Cache) (*Cves, error) { // TODO: implement opts
	// Log all CvesRequest fields using safe function
	//logCvesRequestFields(req)

	// // Log CSAF information for each CVE in the request
	// for _, cve := range req.Cves {
	// 	csafInfo := getCSAFInfoForCVE(c, cve)
	// 	utils.LogInfo("🔍 [CSAF-INFO] CVE:", cve)
	// 	utils.LogInfo("🔍 [CSAF-INFO] Found in CSAF:", fmt.Sprintf("%t", csafInfo["found"]))
	// 	if csafInfo["found"].(bool) {
	// 		utils.LogInfo("🔍 [CSAF-INFO] CVE ID:", fmt.Sprintf("%d", csafInfo["cve_id"]))
	// 		utils.LogInfo("🔍 [CSAF-INFO] Total Products:", fmt.Sprintf("%d", csafInfo["total_products"]))
	// 	} else {
	// 		utils.LogInfo("🔍 [CSAF-INFO] Message:", csafInfo["message"].(string))
	// 	}
	// }

	cves := req.Cves
	if len(cves) == 0 {
		return &Cves{}, errors.Wrap(ErrProcessingInput, "'cve_list' is a required property")
	}

	cves, err := utils.TryExpandRegexPattern(cves, c.CveDetail)
	if err != nil {
		return &Cves{}, errors.Wrap(ErrProcessingInput, "invalid regex pattern")
	}
	// utils.LogInfo(" [CVE-REQUEST] After regex expansion:", "expanded_cves_count", len(cves))

	cves = filterInputCves(c, cves, req)
	// utils.LogInfo(" [CVE-REQUEST] After filtering:", "filtered_cves_count", len(cves))

	slices.Sort(cves)
	cves, pagination := utils.Paginate(cves, req.PaginationRequest)
	// utils.LogInfo("[CVE-REQUEST] Final result:", "final_cves_count", len(cves), "pagination", pagination)

	res := Cves{
		Cves:       c.getCveDetails(cves),
		LastChange: c.DBChange.LastChange,
		Pagination: pagination,
	}

	// Log the result structure
	utils.LogInfo("🔍 [CVE-RESULT] Final result structure:")
	utils.LogInfo("🔍 [CVE-RESULT] CVE Count:", fmt.Sprintf("%d", len(res.Cves)))
	utils.LogInfo("🔍 [CVE-RESULT] Last Change:", res.LastChange.Format(time.RFC3339))
	utils.LogInfo("🔍 [CVE-RESULT] Page Number:", fmt.Sprintf("%d", res.PageNumber))
	utils.LogInfo("🔍 [CVE-RESULT] Page Size:", fmt.Sprintf("%d", res.PageSize))
	utils.LogInfo("🔍 [CVE-RESULT] Total Pages:", fmt.Sprintf("%d", res.TotalPages))

	// Log each CVE in the result
	for cveName, cveDetail := range res.Cves {
		utils.LogInfo("🔍 [CVE-RESULT] CVE:", cveName)
		utils.LogInfo("🔍 [CVE-RESULT] Impact:", cveDetail.Impact)
		utils.LogInfo("🔍 [CVE-RESULT] CVSS3 Score:", cveDetail.Cvss3Score)
		utils.LogInfo("🔍 [CVE-RESULT] Errata Count:", fmt.Sprintf("%d", len(cveDetail.Errata)))
		utils.LogInfo("🔍 [CVE-RESULT] Packages Count:", fmt.Sprintf("%d", len(cveDetail.Packages)))
		utils.LogInfo("🔍 [CVE-RESULT] Source Packages Count:", fmt.Sprintf("%d", len(cveDetail.SourcePackages)))
		if len(cveDetail.Errata) > 0 {
			utils.LogInfo("🔍 [CVE-RESULT] Errata List:", strings.Join(cveDetail.Errata, ","))
		}
		if len(cveDetail.Packages) > 0 {
			utils.LogInfo("🔍 [CVE-RESULT] Package List:", strings.Join(cveDetail.Packages, ","))
		}
	}

	utils.LogInfo("🔍 [CVE-RESULT] END OF RESULT")

	return &res, nil
}
