# JBlog: A Simple Go Blogging Platform

JBlog is a straightforward blogging platform built with Go, allowing users to create, edit, and view blog posts. It offers a clean and efficient way to manage and publish content online.

## Features

* **User Authentication:** Securely manage user accounts and access control. Supports Basic Auth.
* **Content Creation and Management:** Easily create, edit, and delete blog posts with a user-friendly interface.
* **Markdown Support:** Write blog content using Markdown for rich formatting and easy content creation.
* **Administrative Interface:** Basic administrative functions for managing users and posts.
* **Post Sorting:** Posts are sorted by date, with the newest posts appearing first.

## Getting Started

### Prerequisites

* Go 1.21 or later

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/jpells/jblog.git
   cd jblog
   ```

2. Install dependencies:
   ```bash
   go mod tidy
   go mod download
   ```

3. Build the application:
   ```bash
   go build -o jblog
   ```

4. Run the application:
   ```bash
   ./jblog
   ```

### Usage

1. Open your web browser and navigate to `http://localhost:8100`.
2. To access the admin interface, go to `http://localhost:8100/admin` and log in with the default credentials (username: `admin`, password: `changeme`).
3. Create, edit, and delete blog posts through the admin interface.

### Running Tests

To run the tests, use the following command:

```bash
go test ./...
```

## Acknowledgments

Special thanks to large language models (LLMs) for assisting in the rapid development of this application. Without their help, this project would have taken much longer and involved significantly more coffee.

## License

This project is licensed under the MIT License. This means you are free to use, modify, and distribute this software, provided that you include the original copyright and license notice in any copies or substantial portions of the software.

For more details, see the [LICENSE](LICENSE) file.