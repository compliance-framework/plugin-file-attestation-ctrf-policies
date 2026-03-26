package compliance_framework.ctrf_errors

# test ctrf_contains_error when there is an error-level result
test_ctrf_contains_error_true if {
  ctrf := {
    "results": 
      {
        "summary": 
          {"failed": 1},
      },
  }

  ctrf_failed_tests(ctrf)
}

# test ctrf_contains_error fails as invalid ctrf type
test_ctrf_fail_if_not_a_ctrf if {
  inp := {
    "path":   "main.go",
    "exists": true,
    "content": "not a ctrf",
  }

  violation[v] with input as inp
  v.id == "ctrf_report_unparsable"
  v.remarks == "File isn't a valid CTRF report."
}

# test ctrf_contains_error fails as invalid ctrf type
test_ctrf_fail_if_json_not_a_ctrf if {
  ctrf := {
    "not": {
      "a": {
        "ctrf":  "here"
      }
    }
  }
  inp := {
    "path":   "main.go",
    "exists": true,
    "content": json.marshal(ctrf),
  }

  violation[v] with input as inp
  v.id == "ctrf_report_invalid"
  v.remarks == "File isn't a valid CTRF report."
}

# test ctrf_contains_error fails as invalid ctrf type
test_ctrf_fail_if_json_not_a_ctrf_summary_missing if {
  ctrf := {
    "results": {
      "foo": "bar"
    }
  }
  ctrf_is_invalid(ctrf)
}

# test ctrf_contains_error fails as invalid ctrf type
test_ctrf_fail_if_json_not_a_ctrf_failed_missing if {
  ctrf := {
    "results": {
      "summary": {
              "total": 5,
              "passed": 5
      }
    }
  }
  ctrf_is_invalid(ctrf)
}

# test for a valid ctrf
test_ctrf_is_valid if {
  ctrf := {
    "results": {
      "summary": {
              "failed": 0
      }
    }
  }
  not ctrf_is_invalid(ctrf)
}

# test violation fires when file exists and ctrf has an error
test_violation_when_error_and_file_exists if {
  ctrf := {
    "results":
      {
        "summary":
          {"failed": 5},
      },
  }

  inp := {
    "path":   "main.go",
    "exists": true,
    "content": json.marshal(ctrf),
  }

  violation[v] with input as inp
  v.id == "ctrf_report_failed_tests"
  v.remarks == "CTRF report contains at least one failed test"
}
