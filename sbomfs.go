// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2025 The Carabiner Authors

// Package sbomfs implements an fs.FS backed by protobom SBOM node properties.
//
// Files are stored as properties on the root nodes of an SBOM document.
// A property with Name "sbomfs:hello.txt" and Data containing base64-encoded
// bytes represents a file named "hello.txt" with those decoded bytes as content.
package sbomfs

import (
	"encoding/base64"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/protobom/protobom/pkg/sbom"
)

const propertyPrefix = "sbomfs:"

// FS implements fs.FS, fs.ReadFileFS, and fs.ReadDirFS backed by protobom
// SBOM node properties. Files are stored as base64-encoded property values
// on the document's root nodes.
type FS struct {
	doc *sbom.Document
}

// New creates a new FS from the given protobom document.
func New(doc *sbom.Document) *FS {
	return &FS{doc: doc}
}

// Open opens the named file. It implements fs.FS.
func (f *FS) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}

	// Root directory
	if name == "." {
		return f.openDir()
	}

	// No subdirectories yet — reject paths with slashes.
	if strings.Contains(name, "/") {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}

	data, err := f.readProperty(name)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}

	return &file{
		name: name,
		data: data,
	}, nil
}

// ReadFile reads the named file and returns its contents. It implements fs.ReadFileFS.
func (f *FS) ReadFile(name string) ([]byte, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "read", Path: name, Err: fs.ErrInvalid}
	}
	if name == "." {
		return nil, &fs.PathError{Op: "read", Path: name, Err: fs.ErrInvalid}
	}
	if strings.Contains(name, "/") {
		return nil, &fs.PathError{Op: "read", Path: name, Err: fs.ErrNotExist}
	}

	data, err := f.readProperty(name)
	if err != nil {
		return nil, &fs.PathError{Op: "read", Path: name, Err: err}
	}
	return data, nil
}

// ReadDir reads the root directory and returns its entries. It implements fs.ReadDirFS.
func (f *FS) ReadDir(name string) ([]fs.DirEntry, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrInvalid}
	}
	if name != "." {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrNotExist}
	}

	entries := []fs.DirEntry{}
	seen := map[string]struct{}{}

	for _, node := range f.doc.GetRootNodes() {
		for _, prop := range node.GetProperties() {
			fname, ok := propertyFileName(prop)
			if !ok {
				continue
			}
			if _, exists := seen[fname]; exists {
				continue
			}
			seen[fname] = struct{}{}

			data, err := base64.StdEncoding.DecodeString(prop.GetData())
			if err != nil {
				continue
			}

			entries = append(entries, &dirEntry{
				name: fname,
				size: int64(len(data)),
			})
		}
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	return entries, nil
}

// WriteFile writes data to the named file, creating it if it doesn't exist
// or overwriting it if it does. The data is base64-encoded and stored as a
// property on the first root node of the document.
func (f *FS) WriteFile(name string, data []byte) error {
	if !fs.ValidPath(name) || name == "." || strings.Contains(name, "/") {
		return &fs.PathError{Op: "write", Path: name, Err: fs.ErrInvalid}
	}

	encoded := base64.StdEncoding.EncodeToString(data)
	propName := propertyPrefix + name

	// Try to update an existing property first.
	for _, node := range f.doc.GetRootNodes() {
		for _, prop := range node.GetProperties() {
			if prop.GetName() == propName {
				prop.Data = encoded
				return nil
			}
		}
	}

	// Property doesn't exist — create it on the first root node.
	roots := f.doc.GetRootNodes()
	if len(roots) == 0 {
		return fmt.Errorf("sbomfs: document has no root nodes")
	}

	roots[0].Properties = append(roots[0].Properties, &sbom.Property{
		Name: propName,
		Data: encoded,
	})
	return nil
}

// RemoveFile removes the named file from the filesystem.
func (f *FS) RemoveFile(name string) error {
	if !fs.ValidPath(name) || name == "." || strings.Contains(name, "/") {
		return &fs.PathError{Op: "remove", Path: name, Err: fs.ErrInvalid}
	}

	propName := propertyPrefix + name

	for _, node := range f.doc.GetRootNodes() {
		for i, prop := range node.GetProperties() {
			if prop.GetName() == propName {
				node.Properties = append(node.Properties[:i], node.GetProperties()[i+1:]...)
				return nil
			}
		}
	}

	return &fs.PathError{Op: "remove", Path: name, Err: fs.ErrNotExist}
}

// readProperty finds and decodes the first matching sbomfs property across root nodes.
func (f *FS) readProperty(name string) ([]byte, error) {
	propName := propertyPrefix + name

	for _, node := range f.doc.GetRootNodes() {
		for _, prop := range node.GetProperties() {
			if prop.GetName() == propName {
				data, err := base64.StdEncoding.DecodeString(prop.GetData())
				if err != nil {
					return nil, fmt.Errorf("decoding base64 data for %q: %w", name, err)
				}
				return data, nil
			}
		}
	}
	return nil, fs.ErrNotExist
}

// propertyFileName returns the filename from a property if it has the sbomfs prefix.
func propertyFileName(prop *sbom.Property) (string, bool) {
	if !strings.HasPrefix(prop.GetName(), propertyPrefix) {
		return "", false
	}
	name := strings.TrimPrefix(prop.GetName(), propertyPrefix)
	if name == "" {
		return "", false
	}
	return name, true
}

// file implements fs.File for an in-memory file.
type file struct {
	name   string
	data   []byte
	offset int
}

func (f *file) Stat() (fs.FileInfo, error) {
	return &fileInfo{name: f.name, size: int64(len(f.data))}, nil
}

func (f *file) Read(b []byte) (int, error) {
	if f.offset >= len(f.data) {
		return 0, io.EOF
	}
	n := copy(b, f.data[f.offset:])
	f.offset += n
	return n, nil
}

func (f *file) Close() error {
	return nil
}

// dir implements fs.File and fs.ReadDirFile for the root directory.
type dir struct {
	entries []fs.DirEntry
	offset  int
}

func (d *dir) Stat() (fs.FileInfo, error) {
	return &fileInfo{name: ".", isDir: true}, nil
}

func (d *dir) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: ".", Err: fs.ErrInvalid}
}

func (d *dir) Close() error {
	return nil
}

func (d *dir) ReadDir(n int) ([]fs.DirEntry, error) {
	if n <= 0 {
		entries := d.entries[d.offset:]
		d.offset = len(d.entries)
		return entries, nil
	}

	if d.offset >= len(d.entries) {
		return nil, io.EOF
	}

	end := d.offset + n
	if end > len(d.entries) {
		end = len(d.entries)
	}
	entries := d.entries[d.offset:end]
	d.offset = end

	if d.offset >= len(d.entries) {
		return entries, io.EOF
	}
	return entries, nil
}

func (f *FS) openDir() (fs.File, error) {
	entries, err := f.ReadDir(".")
	if err != nil {
		return nil, err
	}
	return &dir{entries: entries}, nil
}

// fileInfo implements fs.FileInfo.
type fileInfo struct {
	name  string
	size  int64
	isDir bool
}

func (fi *fileInfo) Name() string       { return fi.name }
func (fi *fileInfo) Size() int64        { return fi.size }
func (fi *fileInfo) Mode() fs.FileMode  { return 0o444 }
func (fi *fileInfo) ModTime() time.Time { return time.Time{} }
func (fi *fileInfo) IsDir() bool        { return fi.isDir }
func (fi *fileInfo) Sys() any           { return nil }

// dirEntry implements fs.DirEntry.
type dirEntry struct {
	name string
	size int64
}

func (de *dirEntry) Name() string               { return de.name }
func (de *dirEntry) IsDir() bool                { return false }
func (de *dirEntry) Type() fs.FileMode          { return 0 }
func (de *dirEntry) Info() (fs.FileInfo, error) { return &fileInfo{name: de.name, size: de.size}, nil }
