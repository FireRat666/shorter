[![Go Report Card](https://goreportcard.com/badge/github.com/FireRat666/shorter)](https://goreportcard.com/report/github.com/FireRat666/shorter)
![Linux](https://img.shields.io/badge/Supports-Linux-green.svg)
![windows](https://img.shields.io/badge/Supports-windows-green.svg)
[![License](https://img.shields.io/badge/License-UNLICENSE-blue.svg)](https://raw.githubusercontent.com/FireRat666/shorter/master/UNLICENSE)
[![License](https://img.shields.io/badge/License-0BSD-blue.svg)](https://raw.githubusercontent.com/FireRat666/shorter/master/LICENSE)
# shorter
A powerful, self-hostable link shortener and text sharing service with multi-domain support.

## Features

### Core Functionality
*   **URL & Text Sharing**: Create short links or share text snippets with configurable timeouts and key lengths.
*   **Custom Keys & Usage Limits**: Define your own memorable keys and set a maximum number of uses for any link.
*   **File Sharing (Optional)**: A configurable feature to allow temporary hosting and sharing of files, with an intermediate download page for user safety.
*   **Password-Protected Links**: Secure links with a password, requiring visitors to enter it before being redirected.
*   **QR Code Generation**: Automatically generates a scannable QR code for each created short link.
*   **Quick Add**: Create short links on the fly with a simple GET request to the root URL.
*   **Link Inspection**: Safely inspect the destination of a short link by appending a `~` to the key.

### Administration & Management
*   **Secure Admin Panel**: A modern, session-based admin interface for managing the entire service.
    *   **Subdomain Management**: Create, delete, and configure settings for multiple domains from a single interface.
    *   **Per-Domain Configuration**: Override default settings for link timeouts, display values, and usage limits on a per-subdomain basis.
    *   **"Remember Me"**: Stay logged into the admin panel for an extended period.
    *   **Two-Factor Authentication (2FA)**: Secure the admin account with Time-based One-Time Passwords (TOTP) from an authenticator app.
    *   **Link Management**: A paginated and searchable interface to view, edit, and perform bulk deletions of links for each domain.
    *   **API Key Management**: A paginated and searchable interface to create, manage, and delete API keys with descriptions.
*   **Advanced Analytics**: A dedicated statistics page provides a comprehensive overview of site activity. All sections load on-demand for a fast user experience and feature:
    *   Overall site-wide totals for active links and clicks.
    *   Recent activity (links created, expired, clicks) over various timeframes.
    *   A paginated viewer for all active links, sorted by popularity.
    *   A breakdown of active links per creator, including individual API keys.
    *   A per-domain statistics viewer.
    *   A feature to safely reset all historical statistics.
*   **Automatic Database Maintenance**: A background job periodically cleans up expired records, and an intelligent "just-in-time" cleanup mechanism reclaims keys from expired links during normal use.

### Security & Deployment
*   **Secure by Default**: Implements a strict Content Security Policy (CSP), CSRF protection on all forms, and other security headers to protect users.
*   **Malware Protection**: Integrated with DNS-based blocklists (DNSBL) to prevent shortening of malicious URLs.
*   **Persistent Storage**: Uses a PostgreSQL backend to store all links, sessions, and configurations.
*   **Resource Management**: Configurable size limits for URL and text submissions to prevent abuse and manage database size.
*   **Deployment Ready**: Designed for modern deployment platforms like Render, with full support for configuration via environment variables.

### Extensibility
*   **Public API**: A RESTful API for programmatic link creation, authenticated with secure bearer tokens.
*   **Customizable Theming**: Override the default HTML templates with your own to match your brand.

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

You can quickly create a short, random-key link by making a GET request to the root of the service with the URL to shorten as the query string. This will create a link with the shortest default timeout.

When using a command-line tool like `curl`, `wget`, or PowerShell's `Invoke-WebRequest`, the service will attempt to detect it and respond with the short URL as plain text, suitable for scripting.

For a service running at `shorter.example.com`, you can use `curl` or your browser:

```bash
    # Using curl will return the short URL as plain text
    curl "https://shorter.example.com/?https://www.google.com"
    # Output: https://shorter.example.com/aBcDeF

    # Visiting the same URL in a browser will show a confirmation page.
```

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

*   `ADMIN_TOTP_ENABLED` & `ADMIN_TOTP_SECRET` (Optional):
    *   **Value**: To enable 2FA, set `ADMIN_TOTP_ENABLED` to `true` and provide a secret for `ADMIN_TOTP_SECRET`.
    *   **How to Generate a Secret**:
        1.  Create a temporary file named `generatesecret.go`.
        2.  Paste the following Go code into it:
            ```go
            package main

            import (
                "crypto/rand"
                "encoding/base32"
                "fmt"
                "log"
            )

            func main() {
                secret := make([]byte, 20)
                if _, err := rand.Read(secret); err != nil {
                    log.Fatalln("Error generating random secret:", err)
                }
                fmt.Println(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret))
            }
            ```
        3.  Run the script from your terminal: `go run generatesecret.go`
        4.  Copy the output secret (e.g., `JBSWY3DPEHPK3PXP...`) and use it as the value for this environment variable.

Render will automatically set the `PORT` environment variable, which the application is configured to use.

### 5. Deploy
With the configuration and environment variables set, you can trigger your first deployment. The application will start, connect to the database, and be available at your Render URL.

## Public API

The service provides a simple RESTful API for programmatic link creation.

### Authentication

Authentication is handled via Bearer tokens. You can generate and manage your API keys from the "API Management" section of the admin panel.

All API requests must include an `Authorization` header with your key:

`Authorization: Bearer YOUR_API_KEY_HERE`

### Endpoint: Create Link

*   **URL**: `/api/v1/links`
*   **Method**: `POST`
*   **Headers**:
    *   `Content-Type: application/json`
    *   `Authorization: Bearer YOUR_API_KEY_HERE`
*   **Body (JSON)**:

| Field | Type | Required | Description |
|---|---|---|---|
| `url` | string | Yes | The destination URL to shorten. |
| `domain` | string | No | The domain to use for the short link. Defaults to the service's primary domain. |
| `custom_key` | string | No | A specific key to use for the short link. If not provided, a random key will be generated. |
| `expires_in` | string | No | A Go duration string (e.g., "1h", "30m", "72h"). Defaults to the shortest configured timeout. |
| `max_uses` | int | No | The maximum number of times the link can be used. Defaults to unlimited (0). |
| `password` | string | No | An optional password to protect the link. |

#### Example Request (`curl`)

```bash
curl -X POST "https://shorter.example.com/api/v1/links" \
-H "Authorization: Bearer YOUR_API_KEY_HERE" \
-H "Content-Type: application/json" \
-d '{
  "url": "https://www.google.com",
  "domain": "shorter.example.com",
  "expires_in": "5m",
  "custom_key": "my-api-link"
}'
```

#### Example Success Response (`201 Created`)

```json
{
  "short_url": "https://shorter.example.com/my-api-link",
  "expires_at": "2025-07-31T14:05:00Z"
}
```

## Future Ideas
*   **Abuse Reporting**: Add a form, protected by a captcha, for users to report links that violate the Terms of Service.
*   **Data Visualization**: Continue to expand the data visualization capabilities on the statistics page with more charts and interactive elements.
*   **User Accounts**: Allow non-admin users to register for accounts to manage their own links and API keys, turning the service into a multi-tenant platform.
*   **Link Descriptions**: Add a description field to links to make them easier to identify and manage in the admin panel.
*   **API Rate Limiting**: Implement rate limiting on the public API to prevent abuse and ensure service stability.
*   **API Expansion**: Expand the API to allow reading, updating, and deleting links for more powerful programmatic administration.
*   **Health Check Endpoint**: Create a dedicated `/health` endpoint for automated monitoring by deployment platforms.
*   **Admin Audit Log**: Track all administrative actions (e.g., who deleted a link, changed a setting, or generated an API key) for security and accountability.

## License

The `shorter` project is dual-licensed to the [public domain](UNLICENSE) and under a [zero-clause BSD license](LICENSE). You may choose either license to govern your use of `shorter`.
