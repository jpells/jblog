package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func setupFileSystemStore(t *testing.T) *FileSystemBlogPostStore {
	dir := t.TempDir()
	return NewFileSystemBlogPostStore(dir)
}

func TestFileSystemBlogPostStore_GetAllPosts(t *testing.T) {
	store := setupFileSystemStore(t)

	post1 := BlogPost{
		Title:    "Test Post 1",
		Markdown: "# Test Post 1\nThis is a test post 1.",
		Date:     time.Now(),
	}

	post2 := BlogPost{
		Title:    "Test Post 2",
		Markdown: "# Test Post 2\nThis is a test post 2.",
		Date:     time.Now().Add(1 * time.Hour),
	}

	err := store.CreatePost(post1)
	if err != nil {
		t.Fatalf("Failed to create post 1: %v", err)
	}

	err = store.CreatePost(post2)
	if err != nil {
		t.Fatalf("Failed to create post 2: %v", err)
	}

	// Set the file modification times for GitHub action runner
	post1Filename := strings.ToLower(strings.ReplaceAll(post1.Title, " ", "-")) + ".md"
	post2Filename := strings.ToLower(strings.ReplaceAll(post2.Title, " ", "-")) + ".md"

	err = os.Chtimes(filepath.Join(store.postsDir, post1Filename), post1.Date, post1.Date)
	if err != nil {
		t.Fatalf("Failed to set modification time for post 1: %v", err)
	}

	err = os.Chtimes(filepath.Join(store.postsDir, post2Filename), post2.Date, post2.Date)
	if err != nil {
		t.Fatalf("Failed to set modification time for post 2: %v", err)
	}

	posts, err := store.GetAllPosts()
	if err != nil {
		t.Fatalf("Failed to get all posts: %v", err)
	}

	if len(posts) != 2 {
		t.Errorf("Expected 2 posts, got %d", len(posts))
	}

	if posts[0].Title != post2.Title {
		t.Errorf("Expected first post to be '%s', got '%s'", post2.Title, posts[0].Title)
	}
}

func TestFileSystemBlogPostStore_GetPost(t *testing.T) {
	store := setupFileSystemStore(t)

	post := BlogPost{
		Title:    "Test Post",
		Markdown: "# Test Post\nThis is a test post.",
		Date:     time.Now(),
	}

	err := store.CreatePost(post)
	if err != nil {
		t.Fatalf("Failed to create post: %v", err)
	}

	filename := strings.ToLower(strings.ReplaceAll(post.Title, " ", "-")) + ".md"
	retrievedPost, err := store.GetPost(filename)

	if err != nil {
		t.Fatalf("Failed to get post: %v", err)
	}

	if retrievedPost.Title != post.Title {
		t.Errorf("Expected title '%s', got '%s'", post.Title, retrievedPost.Title)
	}
}

func TestFileSystemBlogPostStore_CreatePost(t *testing.T) {
	store := setupFileSystemStore(t)

	post := BlogPost{
		Title:    "Test Post",
		Markdown: "# Test Post\nThis is a test post.",
		Date:     time.Now(),
	}

	err := store.CreatePost(post)
	if err != nil {
		t.Fatalf("Failed to create post: %v", err)
	}

	filename := strings.ToLower(strings.ReplaceAll(post.Title, " ", "-")) + ".md"
	if _, err := os.Stat(filepath.Join(store.postsDir, filename)); os.IsNotExist(err) {
		t.Errorf("Post file was not created")
	}
}

func TestFileSystemBlogPostStore_UpdatePost(t *testing.T) {
	store := setupFileSystemStore(t)

	post := BlogPost{
		Title:    "Test Post",
		Markdown: "# Test Post\nThis is a test post.",
		Date:     time.Now(),
	}

	err := store.CreatePost(post)
	if err != nil {
		t.Fatalf("Failed to create post: %v", err)
	}

	updatedPost := BlogPost{
		Title:    "Updated Test Post",
		Markdown: "# Updated Test Post\nThis is an updated test post.",
		Date:     time.Now(),
	}

	filename := strings.ToLower(strings.ReplaceAll(post.Title, " ", "-")) + ".md"

	err = store.UpdatePost(filename, updatedPost)
	if err != nil {
		t.Fatalf("Failed to update post: %v", err)
	}

	newFilename := strings.ToLower(strings.ReplaceAll(updatedPost.Title, " ", "-")) + ".md"

	retrievedPost, err := store.GetPost(newFilename)
	if err != nil {
		t.Fatalf("Failed to get post: %v", err)
	}

	if retrievedPost.Title != updatedPost.Title {
		t.Errorf("Expected title '%s', got '%s'", updatedPost.Title, retrievedPost.Title)
	}
}

func TestFileSystemBlogPostStore_DeletePost(t *testing.T) {
	store := setupFileSystemStore(t)

	post := BlogPost{
		Title:    "Test Post",
		Markdown: "# Test Post\nThis is a test post.",
		Date:     time.Now(),
	}

	err := store.CreatePost(post)
	if err != nil {
		t.Fatalf("Failed to create post: %v", err)
	}

	filename := strings.ToLower(strings.ReplaceAll(post.Title, " ", "-")) + ".md"

	err = store.DeletePost(filename)
	if err != nil {
		t.Fatalf("Failed to delete post: %v", err)
	}

	if _, err := os.Stat(filepath.Join(store.postsDir, filename)); !os.IsNotExist(err) {
		t.Errorf("Post file was not deleted")
	}
}
