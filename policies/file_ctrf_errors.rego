package compliance_framework.ctrf_errors

# Policy: ensure the tracked critical file exists in the repository.

risk_templates := [
	{
		"name": "CTRF report invalid or unreadable",
		"title": "Invalid CTRF Test Report",
		"statement": "The tracked CTRF report cannot be parsed or does not match the expected report structure. When test evidence is malformed or incomplete, the framework cannot rely on it to demonstrate that the intended checks actually ran and passed.",
		"likelihood_hint": "medium",
		"impact_hint": "medium",
		"violation_ids": ["ctrf_report_unparsable", "ctrf_report_invalid"],
		"threat_refs": [],
		"remediation": {
			"title": "Produce a valid CTRF report for the tracked file",
			"description": "Ensure the report generator emits valid CTRF JSON and that the report includes the required summary fields so compliance evidence can be evaluated reliably.",
			"tasks": [
				{"title": "Confirm the tracked file path points to the intended test report artifact"},
				{"title": "Verify the report generator is producing valid CTRF JSON output"},
				{"title": "Regenerate and re-publish the report after fixing export or formatting issues"},
			],
		},
	},
	{
		"name": "CTRF report contains failed tests",
		"title": "Failed Tests Reported in CTRF",
		"statement": "The tracked CTRF report records one or more failed tests. This indicates the control, quality gate, or assurance activity represented by that report did not fully pass, so the report should not be treated as compliant evidence until the failures are understood and resolved.",
		"likelihood_hint": "medium",
		"impact_hint": "high",
		"violation_ids": ["ctrf_report_failed_tests"],
		"threat_refs": [],
		"remediation": {
			"title": "Investigate and resolve failed tests in the CTRF report",
			"description": "Review the failing test cases, determine whether they reflect regressions or unmet control requirements, and regenerate the report once the expected test set passes cleanly.",
			"tasks": [
				{"title": "Identify which tests contributed to the failed count in the CTRF report"},
				{"title": "Triage the root cause of each failure and determine whether it reflects a real regression or control gap"},
				{"title": "Fix the underlying issue or update the expected baseline through approved change control"},
				{"title": "Re-run the test suite and confirm the regenerated CTRF report output"},
			],
		},
	},
]

default has_tracked_file := false

has_tracked_file if {
	input.path != ""
}

ctrf_failed_tests(parsed) if {
	failed := parsed.results.summary.failed
	failed > 0
}

ctrf_is_invalid(parsed) if {
	# 1. results is missing
	not parsed.results
}

ctrf_is_invalid(parsed) if {
	# 2. summary is missing
	not parsed.results.summary
}

ctrf_is_invalid(parsed) if {
	# 3. failed is missing
	not parsed.results.summary.failed
}

violation[{"id": "ctrf_report_unparsable", "remarks": "File isn't a valid CTRF report."}] if {
	has_tracked_file
	input.exists
	not json.unmarshal(input.content)
}

violation[{"id": "ctrf_report_invalid", "remarks": "File isn't a valid CTRF report."}] if {
	has_tracked_file
	input.exists
	parsed := json.unmarshal(input.content)
	ctrf_is_invalid(parsed)
}

violation[{"id": "ctrf_report_failed_tests", "remarks": "CTRF report contains at least one failed test"}] if {
	has_tracked_file
	input.exists
	parsed := json.unmarshal(input.content)
	ctrf_failed_tests(parsed)
}

title := "CTRF Report shows no failed tests"

description := "CTRF Report must show no failed tests."
