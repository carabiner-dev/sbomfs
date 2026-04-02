# sbomfs

A    Go filesystem implementation that reads and writes data from a
Software Bill of Materials (SBOMs).

## Purpose

SBOMfs allows applications to store arbitrary data in standard
SBOM files. Undearneath, it uses OpenSSF's
[Protobom](https://github.com/protobom/protobom) stack, making it
format agnostic (SPDX & CycloneDX sboms are supported).

Information stored in the SBOM data is exposed to go programs via
SBOMfs' `io/fs` implementation.

## Example

This example reads an existing SBOM, embeds provenance metadata into it,
and reads it back using the standard `io/fs` interfaces:

```go
package main

import (
	"fmt"
	"io/fs"
	"log"

	"github.com/carabiner-dev/sbomfs"
	"github.com/protobom/protobom/pkg/reader"
)

func main() {
	// Parse an existing SBOM file using protobom's reader.
	r := reader.New()
	doc, err := r.ParseFile("mysbom.spdx.json")
	if err != nil {
		log.Fatal(err)
	}

	// Create the sbomfs filesystem backed by the document.
	sfs := sbomfs.New(doc)

	// Write provenance data into the SBOM.
	provenance := []byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"my-project"}]}`)
	if err := sfs.WriteFile("provenance.intoto.json", provenance); err != nil {
		log.Fatal(err)
	}

	// Read the file back using the standard fs.ReadFile interface.
	data, err := fs.ReadFile(sfs, "provenance.intoto.json")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(data))

	// List all files stored in the SBOM.
	entries, err := fs.ReadDir(sfs, ".")
	if err != nil {
		log.Fatal(err)
	}
	for _, e := range entries {
		fmt.Println(e.Name())
	}
}
```

The module is lightweight, it has Protobom as its only dependency.

## Current Uses

SBOMfs was developed as a component of the
[AMPEL](https://github.com/carabiner-dev/ampel) attestation
[collector](https://github.com/carabiner-dev/collector),
allowing SBOMs to embed attested information.

## License & Contributing

SBOMfs is released under the Apache 2.0 license by Carabiner Systems.
Patches are welcome!
