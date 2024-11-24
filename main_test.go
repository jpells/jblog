package main

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// Test Handlers

func TestHandleHome(t *testing.T) {
	req, rr := createRequestResponse("GET", "/", nil)
	handler := http.HandlerFunc(handleHome)
	handler.ServeHTTP(rr, req)
	checkStatusCode(t, rr, http.StatusOK)
}

func TestHandlePost(t *testing.T) {
	createDummyFile(t, "posts/test-post.md", "# Test Post\nThis is a test post.")
	defer removeDummyFile(t, "posts/test-post.md")

	req, rr := createRequestResponse("GET", "/post/test-post.md", nil)
	handler := http.HandlerFunc(handlePost)
	handler.ServeHTTP(rr, req)
	checkStatusCode(t, rr, http.StatusOK)
}

func TestHandleLogin(t *testing.T) {
	t.Run("GET /login", testHandleLoginGet)
	t.Run("POST /login with invalid credentials", testHandleLoginPostInvalid)
	t.Run("POST /login with valid credentials", testHandleLoginPostValid)
}

func testHandleLoginGet(t *testing.T) {
	req, rr := createRequestResponse("GET", "/login", nil)
	handler := http.HandlerFunc(handleLogin)
	handler.ServeHTTP(rr, req)
	checkStatusCode(t, rr, http.StatusOK)
}

func testHandleLoginPostInvalid(t *testing.T) {
	req, rr := createRequestResponse("POST", "/login", strings.NewReader("username=wronguser&password=wrongpassword"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	handler := http.HandlerFunc(handleLogin)

	handler.ServeHTTP(rr, req)
	checkStatusCode(t, rr, http.StatusSeeOther)
	checkRedirectLocation(t, rr, "/login")
}

func testHandleLoginPostValid(t *testing.T) {
	req, rr := createRequestResponse("POST", "/login", strings.NewReader("username="+username+"&password="+password))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	handler := http.HandlerFunc(handleLogin)

	handler.ServeHTTP(rr, req)
	checkStatusCode(t, rr, http.StatusSeeOther)
	checkRedirectLocation(t, rr, "/admin")
	checkCookie(t, rr, "auth", base64.StdEncoding.EncodeToString([]byte(username+":"+password)))
}

func TestHandleLogout(t *testing.T) {
	req, rr := createRequestResponse("GET", "/logout", nil)
	req.AddCookie(&http.Cookie{Name: "auth", Value: "dummy-auth-value"})

	handler := http.HandlerFunc(handleLogout)

	handler.ServeHTTP(rr, req)
	checkStatusCode(t, rr, http.StatusSeeOther)
	checkClearedCookie(t, rr)
}

func TestHandleAdmin(t *testing.T) {
	req, rr := createRequestResponse("GET", "/admin", nil)
	handler := http.HandlerFunc(handleAdmin)
	handler.ServeHTTP(rr, req)
	checkStatusCode(t, rr, http.StatusOK)
}

func TestHandleCreate(t *testing.T) {
	req, rr := createRequestResponse("GET", "/create", nil)
	handler := http.HandlerFunc(handleCreate)
	handler.ServeHTTP(rr, req)
	checkStatusCode(t, rr, http.StatusMethodNotAllowed)

	req, rr = createRequestResponse("POST", "/create", nil)
	handler.ServeHTTP(rr, req)
	checkStatusCode(t, rr, http.StatusBadRequest)

	req, rr = createRequestResponse("POST", "/create", strings.NewReader("title=Test+Post&content=This+is+a+test+post."))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handler.ServeHTTP(rr, req)
	checkStatusCode(t, rr, http.StatusSeeOther)
	checkFileExists(t, "posts/test-post.md")
	removeDummyFile(t, "posts/test-post.md")
}

// Test Utility Functions

func TestLoadBlogPosts(t *testing.T) {
	createDummyFile(t, "posts/test-post-1.md", "# Test Post 1\nThis is a test post 1.")
	createDummyFile(t, "posts/test-post-2.md", "# Test Post 2\nThis is a test post 2.")

	defer removeDummyFile(t, "posts/test-post-1.md")
	defer removeDummyFile(t, "posts/test-post-2.md")

	posts, err := loadBlogPosts()
	if err != nil {
		t.Fatal(err)
	}

	if len(posts) != 2 {
		t.Errorf("Incorrect number of posts loaded: got %v want %v", len(posts), 2)
	}

	if posts[0].Title != "test-post-2" || posts[1].Title != "test-post-1" {
		t.Error("Posts are not sorted correctly", posts)
	}
}

func TestLoadBlogPost(t *testing.T) {
	createDummyFile(t, "posts/test-post.md", "# Test Post\nThis is a test post.")
	defer removeDummyFile(t, "posts/test-post.md")

	post, err := loadBlogPost("test-post.md")
	if err != nil {
		t.Fatal(err)
	}

	if post.Title != "test-post" || !strings.Contains(string(post.Content), "Test Post") {
		t.Error("Post data is incorrect")
	}
}

func TestBasicAuth(t *testing.T) {
	req, rr := createRequestResponse("GET", "/admin", nil)
	handler := basicAuth(handleAdmin)
	handler.ServeHTTP(rr, req)
	checkStatusCode(t, rr, http.StatusUnauthorized)

	req.AddCookie(&http.Cookie{Name: "auth", Value: base64.StdEncoding.EncodeToString([]byte(username + ":" + password))})

	rr = httptest.NewRecorder()

	handler.ServeHTTP(rr, req)
	checkStatusCode(t, rr, http.StatusOK)
}

func TestIsUserAuthenticated(t *testing.T) {
	req, _ := createRequestResponse("GET", "/", nil)
	if isUserAuthenticated(req) {
		t.Error("User should not be authenticated without a cookie")
	}

	req, _ = createRequestResponse("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "auth", Value: "invalid-cookie-value"})

	if isUserAuthenticated(req) {
		t.Error("User should not be authenticated with an invalid cookie")
	}

	req, _ = createRequestResponse("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "auth", Value: base64.StdEncoding.EncodeToString([]byte(username + ":" + password))})

	if !isUserAuthenticated(req) {
		t.Error("User should be authenticated with a valid cookie")
	}
}

// Helper Functions

func createRequestResponse(method, url string, body io.Reader) (*http.Request, *httptest.ResponseRecorder) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		panic(err)
	}

	return req, httptest.NewRecorder()
}

func checkStatusCode(t *testing.T, rr *httptest.ResponseRecorder, expected int) {
	if status := rr.Code; status != expected {
		t.Errorf("handler returned wrong status code: got %v want %v", status, expected)
	}
}

func checkRedirectLocation(t *testing.T, rr *httptest.ResponseRecorder, expected string) {
	if location := rr.Header().Get("Location"); location != expected {
		t.Errorf("handler returned wrong redirect location: got %v want %v", location, expected)
	}
}

func checkCookie(t *testing.T, rr *httptest.ResponseRecorder, name, expectedValue string) {
	res := rr.Result()
	defer func() {
		err := res.Body.Close()
		if err != nil {
			t.Error(err)
		}
	}()

	cookies := res.Cookies()
	if len(cookies) != 1 {
		t.Errorf("Expected 1 cookie, got %d", len(cookies))
	}

	if cookies[0].Name != name {
		t.Errorf("Expected cookie name '%s', got %s", name, cookies[0].Name)
	}

	if cookies[0].Value != expectedValue {
		t.Errorf("Expected cookie value '%s', got '%s'", expectedValue, cookies[0].Value)
	}
}

func checkClearedCookie(t *testing.T, rr *httptest.ResponseRecorder) {
	res := rr.Result()
	defer func() {
		err := res.Body.Close()
		if err != nil {
			t.Error(err)
		}
	}()

	cookies := res.Cookies()
	if len(cookies) != 1 || cookies[0].MaxAge != -1 || cookies[0].Value != "" {
		t.Error("Cookie was not cleared correctly")
	}
}

func createDummyFile(t *testing.T, path, content string) {
	dir := "posts"

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.Mkdir(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}

	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	// Explicitly set the file modification time for GitHub actions to sort properly
	if err := os.Chtimes(path, time.Now(), time.Now()); err != nil {
		t.Fatal(err)
	}
}

func removeDummyFile(t *testing.T, path string) {
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}

func checkFileExists(t *testing.T, path string) {
	if _, err := os.Stat(path); err != nil {
		t.Error("Post file was not created")
	}
}
