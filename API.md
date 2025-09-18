<!-- markdownlint-disable MD033 -->
# Public API

The service provides a simple RESTful API for programmatic link management.

## Authentication

Authentication is handled via Bearer tokens. You can generate and manage your API keys from the "API Management" section of the admin panel.

All API requests must include an `Authorization` header with your key:

`Authorization: Bearer YOUR_API_KEY_HERE`

### Endpoint: Create Link

* **URL**: `/api/v1/links`
* **Method**: `POST`
* **Headers**:
  * `Content-Type: application/json`
  * `Authorization: Bearer YOUR_API_KEY_HERE`
* **Body (JSON)**:

| Field | Type | Required | Description |
|---|---|---|---|
| `url` | string | Yes | The destination URL to shorten. |
| `domain` | string | No | The domain to use for the short link. Defaults to the service's primary domain. |
| `custom_key` | string | No | A specific key to use for the short link. If not provided, a random key will be generated. |
| `expires_in` | string | No | A Go duration string (e.g., "1h", "30m", "72h"). Defaults to the shortest configured timeout. |
| `max_uses` | int | No | The maximum number of times the link can be used. Defaults to unlimited (0). |
| `password` | string | No | An optional password to protect the link. |

#### Example Create Request

<details>
<summary>Linux/macOS (`curl`)</summary>

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

</details>

<details>
<summary>Windows (`PowerShell`)</summary>

```powershell
$body = @{
    url        = "https://www.google.com"
    domain     = "shorter.example.com"
    expires_in = "5m"
    custom_key = "my-api-link"
} | ConvertTo-Json -Compress

Invoke-RestMethod -Method Post `
    -Uri "https://shorter.example.com/api/v1/links" `
    -Headers @{
        Authorization = "Bearer YOUR_API_KEY_HERE"
        "Content-Type" = "application/json"
    } `
    -Body $body
```

</details>

<details>
<summary>Windows (`CMD`)</summary>

```cmd
curl -X POST "https://shorter.example.com/api/v1/links" ^
-H "Authorization: Bearer YOUR_API_KEY_HERE" ^
-H "Content-Type: application/json" ^
-d "{ \"url\": \"https://www.google.com\", \"domain\": \"shorter.example.com\", \"expires_in\": \"5m\", \"custom_key\": \"my-api-link\" }"
```

</details>

#### Example Success Response (`201 Created`)

```json
{
  "short_url": "https://shorter.example.com/my-api-link",
  "expires_at": "2025-07-31T14:05:00Z"
}
```

### Endpoint: Get Link Details

* **URL**: `/api/v1/links`
* **Method**: `GET`
* **Headers**:
  * `Authorization: Bearer YOUR_API_KEY_HERE`
* **URL Parameters**:

| Parameter | Type | Required | Description |
|---|---|---|---|
| `key` | string | Yes | The key of the link to retrieve. |
| `domain` | string | No | The domain of the link. Defaults to the primary domain. |

#### Example Get Request

<details>
<summary>Linux/macOS (`curl`)</summary>

```bash
curl -X GET "https://shorter.example.com/api/v1/links?key=my-api-link&domain=shorter.example.com" \
-H "Authorization: Bearer YOUR_API_KEY_HERE"
```

</details>

<details>
<summary>Windows (`PowerShell`)</summary>

```powershell
$uri = "https://shorter.example.com/api/v1/links?key=my-api-link&domain=shorter.example.com"
Invoke-RestMethod -Method Get `
    -Uri $uri `
    -Headers @{
        Authorization = "Bearer YOUR_API_KEY_HERE"
}
```

</details>

<details>
<summary>Windows (`CMD`)</summary>

```cmd
curl -X GET "https://shorter.example.com/api/v1/links?key=my-api-link&domain=shorter.example.com" ^
-H "Authorization: Bearer YOUR_API_KEY_HERE"
```

</details>

#### An Example Success Response (`200 OK`)

```json
{
  "key": "my-api-link",
  "domain": "shorter.example.com",
  "link_type": "url",
  "data": "https://www.google.com",
  "has_password": false,
  "created_by": "admin",
  "times_allowed": 0,
  "times_used": 0,
  "expires_at": "2025-07-31T14:05:00Z",
  "created_at": "2025-07-31T14:00:00Z"
}
```

### Endpoint: Update Link

* **URL**: `/api/v1/links`
* **Method**: `PATCH`
* **Headers**:
  * `Content-Type: application/json`
  * `Authorization: Bearer YOUR_API_KEY_HERE`
* **Body (JSON)**:

| Field | Type | Required | Description |
|---|---|---|---|
| `key` | string | Yes | The key of the link to update. |
| `domain` | string | No | The domain of the link. Defaults to the primary domain. |
| `expires_in` | string | No | A Go duration string (e.g., "24h", "7d"). |
| `max_uses` | int | No | A new maximum number of uses. `0` for unlimited. |
| `password` | string | No | A new password to protect the link. |

#### Example Update Request

<details>
<summary>Linux/macOS (`curl`)</summary>

```bash
curl -X PATCH "https://shorter.example.com/api/v1/links" \
-H "Authorization: Bearer YOUR_API_KEY_HERE" \
-H "Content-Type: application/json" \
-d '{
  "key": "my-api-link",
  "domain": "shorter.example.com",
  "expires_in": "48h"
}'
```

</details>

<details>
<summary>Windows (`PowerShell`)</summary>

```powershell
$body = @{
    key        = "my-api-link"
    domain     = "shorter.example.com"
    expires_in = "48h"
} | ConvertTo-Json -Compress

Invoke-RestMethod -Method Patch `
    -Uri "https://shorter.example.com/api/v1/links" `
    -Headers @{
        Authorization = "Bearer YOUR_API_KEY_HERE"
        "Content-Type" = "application/json"
    } `
    -Body $body
```

</details>

<details>
<summary>Windows (`CMD`)</summary>

```cmd
curl -X PATCH "https://shorter.example.com/api/v1/links" ^
-H "Authorization: Bearer YOUR_API_KEY_HERE" ^
-H "Content-Type: application/json" ^
-d "{ \"key\": \"my-api-link\", \"domain\": \"shorter.example.com\", \"expires_in\": \"48h\" }"
```

</details>

#### Example Success Response (`200 OK`)

```json
{
  "short_url": "https://shorter.example.com/my-api-link",
  "expires_at": "2025-08-02T14:00:00Z"
}
```

### Endpoint: Delete Link

* **URL**: `/api/v1/links`
* **Method**: `DELETE`
* **Headers**:
  * `Content-Type: application/json`
  * `Authorization: Bearer YOUR_API_KEY_HERE`
* **Body (JSON)**:

| Field | Type | Required | Description |
|---|---|---|---|
| `key` | string | Yes | The key of the link to delete. |
| `domain` | string | No | The domain of the link to delete. Defaults to the service's primary domain. |

#### Example Delete Request

<details>
<summary>Linux/macOS (`curl`)</summary>

```bash
curl -X DELETE "https://shorter.example.com/api/v1/links" \
-H "Authorization: Bearer YOUR_API_KEY_HERE" \
-H "Content-Type: application/json" \
-d '{
  "key": "my-api-link",
  "domain": "shorter.example.com"
}'
```

</details>

<details>
<summary>Windows (`PowerShell`)</summary>

```powershell
$body = @{
    key    = "my-api-link"
    domain = "shorter.example.com"
} | ConvertTo-Json -Compress

Invoke-RestMethod -Method Delete `
    -Uri "https://shorter.example.com/api/v1/links" `
    -Headers @{
        Authorization = "Bearer YOUR_API_KEY_HERE"
        "Content-Type" = "application/json"
    } `
    -Body $body
```

</details>

<details>
<summary>Windows (`CMD`)</summary>

```cmd
curl -X DELETE "https://shorter.example.com/api/v1/links" ^
-H "Authorization: Bearer YOUR_API_KEY_HERE" ^
-H "Content-Type: application/json" ^
-d "{ \"key\": \"my-api-link\", \"domain\": \"shorter.example.com\" }"
```

</details>

#### Example Success Response (`204 No Content`)

The server will respond with an empty body and a `204 No Content` status code on success.
