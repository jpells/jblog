package main

import (
	"errors"
	"strings"
	"sync"
	"time"

	"html/template"

	"github.com/gomarkdown/markdown"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// InMemoryBlogPostStore is an in-memory implementation of BlogPostStore.
type InMemoryBlogPostStore struct {
	posts map[string]string
	mu    sync.RWMutex
}

// NewInMemoryBlogPostStore creates a new InMemoryBlogPostStore.
func NewInMemoryBlogPostStore() *InMemoryBlogPostStore {
	return &InMemoryBlogPostStore{
		posts: make(map[string]string),
	}
}

// GetAllPosts retrieves all blog posts from the in-memory store.
func (s *InMemoryBlogPostStore) GetAllPosts() ([]BlogPost, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	posts := make([]BlogPost, 0, len(s.posts))
	for id, content := range s.posts {
		posts = append(posts, BlogPost{
			Title:    strings.TrimSuffix(id, ".md"),
			Markdown: content,
			HTML:     template.HTML(markdown.ToHTML([]byte(content), nil, nil)),
			Date:     time.Now(),
			Filename: id,
		})
	}

	return posts, nil
}

// GetPost retrieves a single blog post by ID from the in-memory store.
func (s *InMemoryBlogPostStore) GetPost(id string) (BlogPost, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	content, exists := s.posts[id]
	if !exists {
		return BlogPost{}, errors.New("post not found")
	}

	return BlogPost{
		Title:    cases.Title(language.English).String(strings.ReplaceAll(strings.TrimSuffix(id, ".md"), "-", " ")),
		Markdown: content,
		HTML:     template.HTML(markdown.ToHTML([]byte(content), nil, nil)),
		Date:     time.Now(), // For simplicity, using current time
		Filename: id,
	}, nil
}

// CreatePost creates a new blog post in the in-memory store.
func (s *InMemoryBlogPostStore) CreatePost(post BlogPost) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := strings.ToLower(strings.ReplaceAll(post.Title, " ", "-")) + ".md"
	if _, exists := s.posts[id]; exists {
		return errors.New("post already exists")
	}

	s.posts[id] = post.Markdown

	return nil
}

// UpdatePost updates an existing blog post in the in-memory store.
func (s *InMemoryBlogPostStore) UpdatePost(id string, post BlogPost) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	newID := strings.ToLower(strings.ReplaceAll(post.Title, " ", "-")) + ".md"
	if id != newID {
		if _, exists := s.posts[newID]; exists {
			return errors.New("post with new title already exists")
		}

		delete(s.posts, id)
	}

	s.posts[newID] = post.Markdown

	return nil
}

// DeletePost deletes a blog post from the in-memory store.
func (s *InMemoryBlogPostStore) DeletePost(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.posts, id)

	return nil
}
