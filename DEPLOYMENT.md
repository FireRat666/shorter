## Deployment on Render or Other Services
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

*   `HCAPTCHA_SITE_KEY` & `HCAPTCHA_SECRET_KEY` (Optional):
    *   **Value**: If you enable the `AbuseReporting` feature in your configuration, you must provide your hCaptcha keys. You can get these from the hCaptcha dashboard.
    *   `HCAPTCHA_SITE_KEY` is your public site key.
    *   `HCAPTCHA_SECRET_KEY` is your private secret key. It is strongly recommended to set this as a secret.

Render will automatically set the `PORT` environment variable, which the application is configured to use.

### 5. Deploy
With the configuration and environment variables set, you can trigger your first deployment. The application will start, connect to the database, and be available at your Render URL.