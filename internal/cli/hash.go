package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/Skpow1234/Vaultpack/internal/crypto"
	"github.com/Skpow1234/Vaultpack/internal/util"
	"github.com/spf13/cobra"
)

func newHashCmd() *cobra.Command {
	var (
		inFile   string
		algo     string
		useStdin bool
	)

	cmd := &cobra.Command{
		Use:   "hash",
		Short: "Compute a hash digest for a file",
		Long:  "Compute a cryptographic hash (e.g. SHA-256) of the input file or stdin and print the result.",
		RunE: func(cmd *cobra.Command, args []string) error {
			printer := NewPrinter(flagJSON, flagQuiet)

			if inFile == "" && !useStdin {
				return fmt.Errorf("--in or --stdin is required")
			}
			if inFile != "" && useStdin {
				return fmt.Errorf("--in and --stdin are mutually exclusive")
			}
			if !crypto.SupportedHashAlgo(algo) {
				printer.Error(util.ErrUnsupportedAlgorithm, fmt.Sprintf("algorithm %q is not supported", algo))
				os.Exit(util.ExitUnsupportedVersion)
				return nil
			}

			var (
				reader   io.Reader
				fileName string
				fileSize int64
			)

			if useStdin {
				reader = os.Stdin
				fileName = "stdin"
				fileSize = -1
			} else {
				f, err := os.Open(inFile)
				if err != nil {
					return fmt.Errorf("open input file: %w", err)
				}
				defer f.Close()

				info, err := f.Stat()
				if err != nil {
					return fmt.Errorf("stat input file: %w", err)
				}
				reader = f
				fileName = inFile
				fileSize = info.Size()
			}

			// Use a counting reader to determine size when reading from stdin.
			cr := &countingReader{r: reader}

			digest, err := crypto.HashReader(cr, algo)
			if err != nil {
				return fmt.Errorf("hash: %w", err)
			}

			if fileSize < 0 {
				fileSize = cr.n
			}

			digestB64 := util.B64Encode(digest)

			switch printer.Mode {
			case OutputJSON:
				return printer.JSON(map[string]any{
					"file":       fileName,
					"algo":       algo,
					"digest_b64": digestB64,
					"size":       fileSize,
				})
			default:
				printer.Human("File:   %s", fileName)
				printer.Human("Algo:   %s", algo)
				printer.Human("Digest: %s", digestB64)
				printer.Human("Size:   %d bytes", fileSize)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&inFile, "in", "", "input file to hash")
	cmd.Flags().StringVar(&algo, "algo", "sha256", "hash algorithm (default: sha256)")
	cmd.Flags().BoolVar(&useStdin, "stdin", false, "read from standard input")

	return cmd
}

// countingReader wraps an io.Reader and counts bytes read.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}
