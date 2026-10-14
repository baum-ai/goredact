// Command corpusfiles writes deterministic benchmark corpora as a directory
// of equally sized files for multi-core scanner comparisons.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/baum-ai/goredact/internal/benchcorpus"
)

func main() {
	output := flag.String("output", "", "directory to create corpus files in")
	scenarioName := flag.String("scenario", string(benchcorpus.KeywordDense), "corpus scenario")
	files := flag.Int("files", 64, "number of files")
	fileSize := flag.Int64("file-size", 8<<20, "bytes per file")
	flag.Parse()

	if *output == "" || *files < 1 || *fileSize < 0 {
		fmt.Fprintln(os.Stderr, "output, positive files, and non-negative file-size are required")
		os.Exit(2)
	}
	if err := os.MkdirAll(*output, 0o755); err != nil {
		fatal(err)
	}
	for i := 0; i < *files; i++ {
		reader, err := benchcorpus.Reader(benchcorpus.Scenario(*scenarioName), *fileSize)
		if err != nil {
			fatal(err)
		}
		name := filepath.Join(*output, fmt.Sprintf("corpus-%03d.log", i))
		file, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			fatal(err)
		}
		_, copyErr := io.Copy(file, reader)
		closeErr := file.Close()
		if copyErr != nil {
			fatal(copyErr)
		}
		if closeErr != nil {
			fatal(closeErr)
		}
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
