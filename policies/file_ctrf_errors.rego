package compliance_framework.ctrf_errors

# Policy: ensure the tracked critical file exists in the repository.

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

violation[{"remarks": "File isn't a valid CTRF report."}] if {
  has_tracked_file
  input.exists
  not json.unmarshal(input.content)
}

violation[{"remarks": "File isn't a valid CTRF report."}] if {
  has_tracked_file
  input.exists
  parsed := json.unmarshal(input.content)
  ctrf_is_invalid(parsed)
}
violation[{"remarks": "CTRF report contains at least one failed test"}] if {
  has_tracked_file
  input.exists
  parsed   := json.unmarshal(input.content)
  ctrf_failed_tests(parsed)
}

title := "CTRF Report shows no failed tests"

description := "CTRF Report must show no failed tests."
