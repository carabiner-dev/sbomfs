// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Carabiner Authors

package sbomfs

import (
	"encoding/base64"
	"errors"
	"io"
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/protobom/protobom/pkg/sbom"
)

// newTestDoc creates a test document with a single root node and the given properties.
func newTestDoc(props ...*sbom.Property) *sbom.Document {
	node := &sbom.Node{
		Id:         "test-node-1",
		Name:       "test-package",
		Properties: props,
	}
	return &sbom.Document{
		Metadata: &sbom.Metadata{},
		NodeList: &sbom.NodeList{
			Nodes:        []*sbom.Node{node},
			RootElements: []string{"test-node-1"},
		},
	}
}

func b64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func TestFSOpen(t *testing.T) {
	doc := newTestDoc(
		&sbom.Property{Name: "sbomfs:hello.txt", Data: b64("Hello, World!")},
		&sbom.Property{Name: "other:ignored", Data: "not-base64"},
		&sbom.Property{Name: "sbomfs:data.bin", Data: b64("\x00\x01\x02\x03")},
	)
	sfs := New(doc)

	t.Run("open existing file", func(t *testing.T) {
		f, err := sfs.Open("hello.txt")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()

		data, err := io.ReadAll(f)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != "Hello, World!" {
			t.Errorf("got %q, want %q", data, "Hello, World!")
		}
	})

	t.Run("open non-existent file", func(t *testing.T) {
		_, err := sfs.Open("missing.txt")
		if err == nil {
			t.Fatal("expected error for missing file")
		}
	})

	t.Run("open root dir", func(t *testing.T) {
		f, err := sfs.Open(".")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()

		info, err := f.Stat()
		if err != nil {
			t.Fatal(err)
		}
		if !info.IsDir() {
			t.Error("root should be a directory")
		}
	})

	t.Run("reject invalid path", func(t *testing.T) {
		_, err := sfs.Open("/absolute")
		if err == nil {
			t.Fatal("expected error for invalid path")
		}
	})

	t.Run("reject subdirectory path", func(t *testing.T) {
		_, err := sfs.Open("sub/file.txt")
		if err == nil {
			t.Fatal("expected error for subdirectory path")
		}
	})
}

func TestFSReadFile(t *testing.T) {
	doc := newTestDoc(
		&sbom.Property{Name: "sbomfs:test.txt", Data: b64("test content")},
	)
	sfs := New(doc)

	data, err := sfs.ReadFile("test.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "test content" {
		t.Errorf("got %q, want %q", data, "test content")
	}

	_, err = sfs.ReadFile("missing.txt")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestFSReadDir(t *testing.T) {
	doc := newTestDoc(
		&sbom.Property{Name: "sbomfs:a.txt", Data: b64("aaa")},
		&sbom.Property{Name: "sbomfs:b.txt", Data: b64("bb")},
		&sbom.Property{Name: "other:skip", Data: "value"},
	)
	sfs := New(doc)

	entries, err := sfs.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}

	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}

	names := map[string]bool{}
	for _, e := range entries {
		names[e.Name()] = true
		if e.IsDir() {
			t.Errorf("entry %q should not be a directory", e.Name())
		}
	}

	if !names["a.txt"] || !names["b.txt"] {
		t.Errorf("expected a.txt and b.txt, got %v", names)
	}
}

func TestFSReadDirNonRoot(t *testing.T) {
	sfs := New(newTestDoc())
	_, err := sfs.ReadDir("subdir")
	if err == nil {
		t.Fatal("expected error for non-root ReadDir")
	}
}

func TestFSWriteFile(t *testing.T) {
	doc := newTestDoc()
	sfs := New(doc)

	// Write a new file.
	if err := sfs.WriteFile("new.txt", []byte("new content")); err != nil {
		t.Fatal(err)
	}

	// Read it back.
	data, err := sfs.ReadFile("new.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new content" {
		t.Errorf("got %q, want %q", data, "new content")
	}

	// Overwrite the file.
	if err := sfs.WriteFile("new.txt", []byte("updated")); err != nil {
		t.Fatal(err)
	}

	data, err = sfs.ReadFile("new.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "updated" {
		t.Errorf("got %q, want %q", data, "updated")
	}
}

func TestFSWriteFileNoRoots(t *testing.T) {
	doc := &sbom.Document{
		Metadata: &sbom.Metadata{},
		NodeList: &sbom.NodeList{},
	}
	sfs := New(doc)

	err := sfs.WriteFile("test.txt", []byte("data"))
	if err == nil {
		t.Fatal("expected error when writing to document with no root nodes")
	}
}

func TestFSRemoveFile(t *testing.T) {
	doc := newTestDoc(
		&sbom.Property{Name: "sbomfs:delete-me.txt", Data: b64("gone")},
	)
	sfs := New(doc)

	if err := sfs.RemoveFile("delete-me.txt"); err != nil {
		t.Fatal(err)
	}

	_, err := sfs.ReadFile("delete-me.txt")
	if err == nil {
		t.Fatal("expected error after removing file")
	}

	// Remove non-existent file.
	err = sfs.RemoveFile("missing.txt")
	if err == nil {
		t.Fatal("expected error for removing non-existent file")
	}
}

func TestFSMultipleRootNodes(t *testing.T) {
	node1 := &sbom.Node{
		Id:   "node-1",
		Name: "pkg-1",
		Properties: []*sbom.Property{
			{Name: "sbomfs:from-node1.txt", Data: b64("node1 data")},
		},
	}
	node2 := &sbom.Node{
		Id:   "node-2",
		Name: "pkg-2",
		Properties: []*sbom.Property{
			{Name: "sbomfs:from-node2.txt", Data: b64("node2 data")},
		},
	}
	doc := &sbom.Document{
		Metadata: &sbom.Metadata{},
		NodeList: &sbom.NodeList{
			Nodes:        []*sbom.Node{node1, node2},
			RootElements: []string{"node-1", "node-2"},
		},
	}
	sfs := New(doc)

	// Both files should be readable.
	for _, tc := range []struct {
		name, want string
	}{
		{"from-node1.txt", "node1 data"},
		{"from-node2.txt", "node2 data"},
	} {
		data, err := sfs.ReadFile(tc.name)
		if err != nil {
			t.Errorf("ReadFile(%q): %v", tc.name, err)
			continue
		}
		if string(data) != tc.want {
			t.Errorf("ReadFile(%q) = %q, want %q", tc.name, data, tc.want)
		}
	}

	// ReadDir should list both.
	entries, err := sfs.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Errorf("got %d entries, want 2", len(entries))
	}
}

func TestFSStat(t *testing.T) {
	doc := newTestDoc(
		&sbom.Property{Name: "sbomfs:info.txt", Data: b64("some info")},
	)
	sfs := New(doc)

	f, err := sfs.Open("info.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}

	if info.Name() != "info.txt" {
		t.Errorf("Name() = %q, want %q", info.Name(), "info.txt")
	}
	if info.Size() != 9 {
		t.Errorf("Size() = %d, want 9", info.Size())
	}
	if info.IsDir() {
		t.Error("IsDir() should be false")
	}
	if info.Mode() != 0o444 {
		t.Errorf("Mode() = %v, want 0444", info.Mode())
	}
}

func TestFSTestSuite(t *testing.T) {
	doc := newTestDoc(
		&sbom.Property{Name: "sbomfs:hello.txt", Data: b64("Hello!")},
		&sbom.Property{Name: "sbomfs:empty.txt", Data: b64("")},
	)
	sfs := New(doc)

	if err := fstest.TestFS(sfs, "hello.txt", "empty.txt"); err != nil {
		t.Fatal(err)
	}
}

func TestFileStat(t *testing.T) {
	f := &file{name: "test.txt", data: []byte("hello")}
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Name() != "test.txt" {
		t.Errorf("got name %q", info.Name())
	}
	if info.Size() != 5 {
		t.Errorf("got size %d", info.Size())
	}
}

func TestDirReadDir(t *testing.T) {
	d := &dir{
		entries: []fs.DirEntry{
			&dirEntry{name: "a.txt"},
			&dirEntry{name: "b.txt"},
			&dirEntry{name: "c.txt"},
		},
	}

	// Read 2 at a time.
	entries, err := d.ReadDir(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d, want 2", len(entries))
	}

	// Read remaining — should get 1 + io.EOF.
	entries, err = d.ReadDir(2)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF, got %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d, want 1", len(entries))
	}

	// Read again — should get 0 + io.EOF.
	entries, err = d.ReadDir(2)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF, got %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("got %d, want 0", len(entries))
	}
}
