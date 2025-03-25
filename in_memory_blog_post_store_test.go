package main

import (
	"testing"
	"time"
)

func TestInMemoryBlogPostStore_GetAllPosts(t *testing.T) {
	store := NewInMemoryBlogPostStore()

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

	posts, err := store.GetAllPosts()
	if err != nil {
		t.Fatalf("Failed to get all posts: %v", err)
	}

	if len(posts) != 2 {
		t.Errorf("Expected 2 posts, got %d", len(posts))
	}
}
func TestInMemoryBlogPostStore_GetPost(t *testing.T) {
	store := NewInMemoryBlogPostStore()

	post := BlogPost{
		Title:    "Test Post",
		Markdown: "# Test Post\nThis is a test post.",
		Date:     time.Now(),
	}

	err := store.CreatePost(post)
	if err != nil {
		t.Fatalf("Failed to create post: %v", err)
	}

	retrievedPost, err := store.GetPost("test-post.md")
	if err != nil {
		t.Fatalf("Failed to get post: %v", err)
	}

	if retrievedPost.Title != post.Title {
		t.Errorf("Expected title '%s', got '%s'", post.Title, retrievedPost.Title)
	}
}
func TestInMemoryBlogPostStore_CreatePost(t *testing.T) {
	store := NewInMemoryBlogPostStore()

	post := BlogPost{
		Title:    "Test Post",
		Markdown: "# Test Post\nThis is a test post.",
		Date:     time.Now(),
	}

	err := store.CreatePost(post)
	if err != nil {
		t.Fatalf("Failed to create post: %v", err)
	}

	_, err = store.GetPost("test-post.md")
	if err != nil {
		t.Errorf("Post was not created: %v", err)
	}
}

func TestInMemoryBlogPostStore_UpdatePost(t *testing.T) {
	store := NewInMemoryBlogPostStore()

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

	err = store.UpdatePost("test-post.md", updatedPost)
	if err != nil {
		t.Fatalf("Failed to update post: %v", err)
	}

	retrievedPost, err := store.GetPost("updated-test-post.md")
	if err != nil {
		t.Fatalf("Failed to get post: %v", err)
	}

	if retrievedPost.Title != updatedPost.Title {
		t.Errorf("Expected title '%s', got '%s'", updatedPost.Title, retrievedPost.Title)
	}
}

func TestInMemoryBlogPostStore_DeletePost(t *testing.T) {
	store := NewInMemoryBlogPostStore()

	post := BlogPost{
		Title:    "Test Post",
		Markdown: "# Test Post\nThis is a test post.",
		Date:     time.Now(),
	}

	err := store.CreatePost(post)
	if err != nil {
		t.Fatalf("Failed to create post: %v", err)
	}

	err = store.DeletePost("test-post.md")
	if err != nil {
		t.Fatalf("Failed to delete post: %v", err)
	}

	_, err = store.GetPost("test-post.md")
	if err == nil {
		t.Errorf("Post was not deleted")
	}
}
