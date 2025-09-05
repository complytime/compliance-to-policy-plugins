package server

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Loader struct {
	policyIndex map[string][]Report
}

func NewLoader() *Loader {
	return &Loader{
		policyIndex: make(map[string][]Report),
	}
}

func (fl *Loader) LoadFromDirectory(dir string) error {
	walkFn := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && (strings.HasSuffix(info.Name(), ".json")) {
			file, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			var opaResult Report
			if err := json.Unmarshal(file, &opaResult); err != nil {
				return fmt.Errorf("failed to unmarshal opa results for %s: %w", info.Name(), err)
			}

			policyId := strings.TrimSuffix(info.Name(), ".json")

			results, ok := fl.policyIndex[policyId]
			if !ok {
				results = []Report{}
			}
			results = append(results, opaResult)
			fl.policyIndex[policyId] = results
		}
		return nil
	}

	err := filepath.Walk(dir, walkFn)
	if err != nil {
		return err
	}

	return nil
}

func (fl *Loader) ResultsByPolicyId(policyId string) []Report {
	results := fl.policyIndex[policyId]
	return results
}
