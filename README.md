[![Go Report Card](https://goreportcard.com/badge/github.com/FireRat666/shorter)](https://goreportcard.com/report/github.com/FireRat666/shorter)
![Linux](https://img.shields.io/badge/Supports-Linux-green.svg)
![windows](https://img.shields.io/badge/Supports-windows-green.svg)
[![License](https://img.shields.io/badge/License-UNLICENSE-blue.svg)](https://raw.githubusercontent.com/FireRat666/shorter/master/UNLICENSE)
[![License](https://img.shields.io/badge/License-0BSD-blue.svg)](https://raw.githubusercontent.com/FireRat666/shorter/master/LICENSE)
# shorter
A powerful, self-hostable link shortener and text sharing service with multi-domain support.

## Features
*   **URL Shortening**: Create short links with configurable timeouts and key lengths.
*   **Text Sharing**: Share snippets of text with the same expiration and usage controls as links.
*   **Custom Keys**: Define your own memorable keys for important links.
*   **Usage Limits**: Set a maximum number of times a link can be accessed before it becomes invalid.
*   **Link Inspection**: Safely inspect the destination of a short link by appending a `~` to the key.
*   **Quick Add**: Create short links on the fly with a simple GET request.
*   **Secure Admin Panel**: A modern, session-based admin interface for managing the service.
    *   **Subdomain Management**: Create, delete, and configure settings for multiple domains from a single interface.
    *   **Per-Domain Configuration**: Override default settings for link timeouts, display values, and usage limits on a per-subdomain basis.
    *   **Link Management**: View and delete active dynamic links and manage permanent static links for each domain.
*   **Persistent Storage**: Uses a PostgreSQL backend to store all links, sessions, and configurations.
*   **Malware Protection**: Integrated with DNS-based blocklists (DNSBL) to prevent shortening of malicious URLs, using the service from [blocklist.de](https://www.blocklist.de/en/rbldns.html).
*   **Customizable Theming**: Override the default HTML templates with your own to match your brand.
*   **Deployment Ready**: Designed for modern deployment platforms like Render, with full support for configuration via environment variables.
*   **Secure by Default**: Implements a strict Content Security Policy (CSP) and other security headers to protect users.

## Installation

```bash
git clone https://github.com/FireRat666/shorter.git
cd shorter
```

## Usage

The application is configured via a local file in the shorterdata directory.

If it doesn't exist, copy shorterdata/config.yaml to shorterdata/Config (note the capital 'C' and no extension). This local file is git-ignored and should contain your secrets.

Edit shorterdata/Config with your local settings, especially the DatabaseURL.

Run the application from the root of the project:

```bash
    go run .
```

The application will automatically find the `shorterdata` directory and start the server.

### Quick Add Feature

You can quickly create a short, random-key link by making a GET request to the root of the service with the URL to shorten as the query string. This will create a link with the shortest default timeout. Note: This method does not support custom keys.

For a service running at `shorter.example.com`, you can use `curl` or your browser:

```bash
    curl "https://shorter.example.com/?https://www.google.com"
```

The service will respond with a page showing the newly created short link.

## Deployment on Render
This application is designed to be easily deployed as a Web Service on Render.

### 1. Fork the Repository
First, fork this repository to your own GitHub account.

### 2. Create a PostgreSQL Database
1.  From your Render dashboard, create a new **PostgreSQL** database.
2.  Give it a name (e.g., `shorter-db`).
3.  Once the database is created, find the **Internal Database URL** under the "Connect" section. You will need this for the next step.

### 3. Create a Web Service
1.  From your Render dashboard, create a new **Web Service**.
2.  Connect the GitHub repository you forked.
3.  Render should automatically detect that this is a Go project. Use the following settings to ensure the output is named correctly:
    *   **Build Command**: `go build -o app .`
    *   **Start Command**: `./app`

### 4. Configure Environment Variables
In your Web Service's "Environment" tab, add the following environment variables. It's important to set these as secrets.

*   `DATABASE_URL`:
    *   **Value**: Paste the **Internal Database URL** you copied from your PostgreSQL instance in step 2.
*   `LOG_SEP`:
    *   **Value**: This should be a long, random, secret string. You can generate one locally using a command like `openssl rand -hex 16`.

*   `SHORTER_DOMAINS`:
    *   **Value**: A comma-separated list of the domains your service will run on. For a new Render service, this would be your `onrender.com` URL (e.g., `shorter-app.onrender.com`). If you add a custom domain later, you can add it here (e.g., `shorter-app.onrender.com,s.example.com`).

*   `ADMIN_USER`:
    *   **Value**: The username for the admin panel (e.g., `admin`).
*   `ADMIN_PASS_HASH`:
    *   **Value**: A **bcrypt hash** of your desired password. For security, you should never use a plaintext password.
    *   **How to Generate a Hash**:
        1.  Create a temporary file named `hash.go`.
        2.  Paste the following Go code into it:
            ```go
            package main

            import (
                "fmt"
                "log"
                "os"
                "golang.org/x/crypto/bcrypt"
            )

            func main() {
                if len(os.Args) < 2 {
                    log.Fatalln("Usage: go run hash.go <your-secret-password>")
                }
                password := os.Args[1]
                hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
                if err != nil {
                    log.Fatalln("Error generating hash:", err)
                }
                fmt.Println(string(hash))
            }
            ```
        3.  Run the script from your terminal: `go run hash.go "my-super-secret-password"`
        4.  Copy the output hash and use it as the value for this environment variable.

Render will automatically set the `PORT` environment variable, which the application is configured to use.

### 5. Deploy
With the configuration and environment variables set, you can trigger your first deployment. The application will start, connect to the database, and be available at your Render URL.

## Future Ideas
*   **Link Analytics**: Track the number of clicks for each link to provide basic usage statistics.
*   **Password-Protected Links**: Add an option to require a password before a user can be redirected to the destination URL.
*   **QR Code Generation**: Automatically generate a downloadable QR code for each created short link.
*   **Periodic Cleanup**: Add a background job to periodically clean up expired links and sessions from the database, in addition to the current startup cleanup.
*   **"Remember Me"**: Add a "Remember Me" option to the login page to allow for longer-lived sessions.
*   **Public API**: Create a RESTful API for programmatic link creation and management, protected by API keys.
*   **Abuse Reporting**: Add a form, protected by a captcha, for users to report links that violate the Terms of Service.

## License

The `shorter` project is dual-licensed to the [public domain](UNLICENSE) and under a [zero-clause BSD license](LICENSE). You may choose either license to govern your use of `shorter`.
