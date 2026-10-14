package rules

// The built-in rule tables (zz_generated_rules.go, zz_generated_fixtures_test.go)
// are produced from the declarative specs in ./specs by tools/rulegen. Run
// `go generate ./internal/rules` after editing any file under ./specs.
//
//go:generate go run github.com/baum-ai/goredact/tools/rulegen -specs ./specs -out ./zz_generated_rules.go -fixtures ./zz_generated_fixtures_test.go
