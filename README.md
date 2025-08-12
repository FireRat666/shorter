# shorter

[![Go Report Card](https://goreportcard.com/badge/github.com/FireRat666/shorter)](https://goreportcard.com/report/github.com/FireRat666/shorter)
![Linux](https://img.shields.io/badge/Supports-Linux-green.svg)
![windows](https://img.shields.io/badge/Supports-windows-green.svg)
[![License](https://img.shields.io/badge/License-UNLICENSE-blue.svg)](https://raw.githubusercontent.com/FireRat666/shorter/master/UNLICENSE)
[![License](https://img.shields.io/badge/License-0BSD-blue.svg)](https://raw.githubusercontent.com/FireRat666/shorter/master/LICENSE)

A powerful, self-hostable link shortener and text sharing service with multi-domain support.

## Features

### Core Functionality

* **URL & Text Sharing**: Create short links or share text snippets with configurable timeouts and key lengths.
* **Custom Keys & Usage Limits**: Define your own memorable keys and set a maximum number of uses for any link.
* **File Sharing (Optional)**: A configurable feature to allow temporary hosting and sharing of files, with an intermediate download page for user safety.
* **Password-Protected Links**: Secure links with a password, requiring visitors to enter it before being redirected.
* **QR Code Generation**: Automatically generates a scannable QR code for each created short link.
* **Quick Add**: Create short links on the fly with a simple GET request to the root URL.
* **Link Inspection**: Safely inspect the destination of a short link by appending a `~` to the key.

### Administration & Management

* **Secure Admin Panel**: A modern, session-based admin interface for managing the entire service.
  * **Subdomain Management**: Create, delete, and configure settings for multiple domains from a single interface.
  * **Per-Domain Configuration**: Override default settings for link timeouts, display values, usage limits, and anonymous user rate limits on a per-subdomain basis.
  * **"Remember Me"**: Stay logged into the admin panel for an extended period.
  * **Two-Factor Authentication (2FA)**: Secure the admin account with Time-based One-Time Passwords (TOTP) from an authenticator app.
  * **Link Management**: A paginated and searchable interface to view, edit, and perform bulk deletions of links for each domain.
  * **API Key Management**: A paginated and searchable interface to create, manage, and delete API keys with descriptions.
  * **Abuse Report Management**: A paginated and searchable interface to review, manage, and delete user-submitted abuse reports.
* **Advanced Analytics**: A dedicated statistics page provides a comprehensive overview of site activity. All sections load on-demand for a fast user experience and feature:
  * Overall site-wide totals for active links and clicks.
  * Recent activity (links created, expired, clicks) over various timeframes.
  * A recent activity chart and a paginated viewer for all active links, sorted by popularity.
  * A breakdown of active links per creator, including individual API keys.
  * A per-domain statistics viewer.
  * A feature to safely reset all historical statistics.
* **Automatic Database Maintenance**: A background job periodically cleans up expired records, and an intelligent "just-in-time" cleanup mechanism reclaims keys from expired links during normal use.

### Security & Deployment

* **Secure by Default**: Implements a strict Content Security Policy (CSP), CSRF protection on all forms, and other security headers to protect users.
* **Malware Protection**: Integrated with DNS-based blocklists (DNSBL) to prevent shortening of malicious URLs.
* **Abuse Reporting**: A public-facing form, protected by hCaptcha, allows users to report malicious links.
* **Persistent Storage**: Uses a PostgreSQL backend to store all links, sessions, and configurations.
* **API Rate Limiting**: Differentiated rate limits for anonymous users and authenticated API clients to prevent abuse and ensure service stability.
* **Resource Management**: Configurable size limits for URL and text submissions to prevent abuse and manage database size.
* **Deployment Ready**: Designed for modern deployment platforms like Render, with full support for configuration via environment variables.

### Extensibility

* **Public API**: A RESTful API for programmatic link creation, deletion, and updating, authenticated with secure bearer tokens.
* **Customizable Theming**: Override the default HTML templates with your own to match your brand.

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

You can quickly create a short, random-key link by making a GET request to the root of the service. This will create a link with a default timeout and key length.

For a service running at `shorter.example.com`, you can use `curl` or your browser:

**Basic Usage (shortest timeout):**

```bash
    # The URL is the raw query string.
    curl "https://shorter.example.com/?https://www.google.com"
    # Output: https://shorter.example.com/a
```

**Advanced Usage (specifying length and timeout):**

You can use query parameters to control the length of the random key and its corresponding timeout.

* `len=1`: Uses `LinkLen1` and `LinkLen1Timeout` (default).
* `len=2`: Uses `LinkLen2` and `LinkLen2Timeout`.
* `len=3`: Uses `LinkLen3` and `LinkLen3Timeout`.
* `len=c`: Uses `LinkLen3` plus a random few characters with the CustomTimeout duration.

```bash
    # Use the 'url' and 'len' parameters.
    curl "https://shorter.example.com/?len=2&url=https://www.google.com"
    # Output: https://shorter.example.com/gH

    # When using a command-line tool like curl, wget, or PowerShell's Invoke-WebRequest, 
    # the service will attempt to detect it and respond with the short URL as plain text, suitable for scripting.
    # Visiting the same URL in a browser will show a confirmation page.
```

## Deployment

This application is designed for easy deployment on modern cloud platforms like Render.

For detailed, step-by-step instructions, please see the **[Deployment Guide](DEPLOYMENT.md)**.

## Public API

For detailed information on using the RESTful API for programmatic link management, please see the **[API Documentation](API.md)**.

## Future Ideas

* **Data Visualization**: Continue to expand the data visualization capabilities on the statistics page with more charts and interactive elements.
* **User Accounts**: Allow non-admin users to register for accounts to manage their own links and API keys, turning the service into a multi-tenant platform.
* **Link Descriptions**: Add a description field to links to make them easier to identify and manage in the admin panel.
* **API Expansion**: Continue to expand the API to allow reading link details for more powerful programmatic administration.
* **Health Check Endpoint**: Create a dedicated `/health` endpoint for automated monitoring by deployment platforms.
* **Admin Audit Log**: Track all administrative actions (e.g., who deleted a link, changed a setting, or generated an API key) for security and accountability.

## License

The `shorter` project is dual-licensed to the [public domain](UNLICENSE) and under a [zero-clause BSD license](LICENSE). You may choose either license to govern your use of `shorter`.
