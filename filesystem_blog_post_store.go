package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"html/template"

	"github.com/gomarkdown/markdown"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// FileSystemBlogPostStore implements BlogPostStore using the file system.
type FileSystemBlogPostStore struct {
	postsDir string
}

// NewFileSystemBlogPostStore creates a new FileSystemBlogPostStore.
func NewFileSystemBlogPostStore(postsDir string) *FileSystemBlogPostStore {
	return &FileSystemBlogPostStore{postsDir: postsDir}
}

// GetAllPosts retrieves all blog posts from the file system.
func (store *FileSystemBlogPostStore) GetAllPosts() ([]BlogPost, error) {
	files, err := filepath.Glob(filepath.Join(store.postsDir, "*.md"))
	if err != nil {
		return nil, err
	}

	posts := make([]BlogPost, 0, len(files))

	for _, file := range files {
		post, err := store.GetPost(filepath.Base(file))
		if err != nil {
			return posts, err
		}

		posts = append(posts, post)
	}

	// Sort posts by descending date
	sort.Slice(posts, func(i, j int) bool {
		return posts[i].Date.After(posts[j].Date)
	})

	return posts, nil
}

// GetPost retrieves a single blog post by filename from the file system.
func (store *FileSystemBlogPostStore) GetPost(filename string) (BlogPost, error) {
	content, err := os.ReadFile(filepath.Join(store.postsDir, filename))
	if err != nil {
		return BlogPost{}, err
	}

	htmlContent := markdown.ToHTML(content, nil, nil)
	title := cases.Title(language.English).String(strings.ReplaceAll(strings.TrimSuffix(filename, ".md"), "-", " "))

	info, err := os.Stat(filepath.Join(store.postsDir, filename))
	if err != nil {
		return BlogPost{}, err
	}

	return BlogPost{
		Title:    title,
		Markdown: string(content),
		HTML:     template.HTML(htmlContent),
		Date:     info.ModTime(),
		Filename: filename,
	}, nil
}

// CreatePost creates a new blog post in the file system.
func (store *FileSystemBlogPostStore) CreatePost(post BlogPost) error {
	filename := strings.ToLower(strings.ReplaceAll(post.Title, " ", "-")) + ".md"
	filepath := filepath.Join(store.postsDir, filename)

	return os.WriteFile(filepath, []byte(post.Markdown), 0600)
}

// UpdatePost updates an existing blog post in the file system.
func (store *FileSystemBlogPostStore) UpdatePost(filename string, post BlogPost) error {
	oldFilepath := filepath.Join(store.postsDir, filename)
	newFilename := strings.ToLower(strings.ReplaceAll(post.Title, " ", "-")) + ".md"
	newFilepath := filepath.Join(store.postsDir, newFilename)

	if err := os.WriteFile(newFilepath, []byte(post.Markdown), 0600); err != nil {
		return err
	}

	if oldFilepath != newFilepath {
		if err := os.Remove(oldFilepath); err != nil {
			return err
		}
	}

	return nil
}

// DeletePost deletes a blog post from the file system.
func (store *FileSystemBlogPostStore) DeletePost(filename string) error {
	return os.Remove(filepath.Join(store.postsDir, filename))
}
