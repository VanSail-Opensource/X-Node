package main

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
)

type apiStatusError struct {
	Status  int
	Method  string
	Path    string
	Details []validationIdentifier
}

type validationIdentifier struct {
	Resource string `json:"resource"`
	Field    string `json:"field"`
	Code     string `json:"code"`
}

func (err apiStatusError) Error() string {
	message := fmt.Sprintf("GitHub API %s %s: status %d", err.Method, err.Path, err.Status)
	for _, detail := range err.Details {
		fields := []string{}
		for _, pair := range [][2]string{{"resource", detail.Resource}, {"field", detail.Field}, {"code", detail.Code}} {
			if pair[1] != "" {
				fields = append(fields, pair[0]+"="+pair[1])
			}
		}
		if len(fields) > 0 {
			message += "; " + strings.Join(fields, " ")
		}
	}
	return message
}

var validationIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9_.\[\]/-]{1,96}$`)

// Validation messages, values, URLs and raw bodies can echo submitted secrets.
// Only bounded 422 resource/field/code identifiers cross the diagnostic boundary.
func validationIdentifiers(body io.Reader) []validationIdentifier {
	const maximum = 64 << 10
	raw, err := io.ReadAll(io.LimitReader(body, maximum+1))
	if err != nil || len(raw) > maximum {
		return nil
	}
	var response struct {
		Errors []json.RawMessage `json:"errors"`
	}
	if json.Unmarshal(raw, &response) != nil {
		return nil
	}
	details := []validationIdentifier{}
	for index, rawDetail := range response.Errors {
		if index >= 8 {
			break
		}
		var detail validationIdentifier
		if json.Unmarshal(rawDetail, &detail) != nil {
			continue
		}
		for _, value := range []*string{&detail.Resource, &detail.Field, &detail.Code} {
			if !validationIdentifierPattern.MatchString(*value) {
				*value = ""
			}
		}
		if detail.Resource != "" || detail.Field != "" || detail.Code != "" {
			details = append(details, detail)
		}
	}
	return details
}
