## Public API

The service provides a simple RESTful API for programmatic link management.

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

### Endpoint: Update Link

*   **URL**: `/api/v1/links`
*   **Method**: `PATCH`
*   **Headers**:
    *   `Content-Type: application/json`
    *   `Authorization: Bearer YOUR_API_KEY_HERE`
*   **Body (JSON)**:

| Field | Type | Required | Description |
|---|---|---|---|
| `key` | string | Yes | The key of the link to update. |
| `domain` | string | No | The domain of the link. Defaults to the primary domain. |
| `expires_in` | string | No | A Go duration string (e.g., "24h", "7d"). |
| `max_uses` | int | No | A new maximum number of uses. `0` for unlimited. |
| `password` | string | No | A new password to protect the link. |

#### Example Request (`curl`)

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

#### Example Success Response (`200 OK`)

```json
{
  "short_url": "https://shorter.example.com/my-api-link",
  "expires_at": "2025-08-02T14:00:00Z"
}
```

### Endpoint: Delete Link

*   **URL**: `/api/v1/links`
*   **Method**: `DELETE`
*   **Headers**:
    *   `Content-Type: application/json`
    *   `Authorization: Bearer YOUR_API_KEY_HERE`
*   **Body (JSON)**:

| Field | Type | Required | Description |
|---|---|---|---|
| `key` | string | Yes | The key of the link to delete. |
| `domain` | string | No | The domain of the link to delete. Defaults to the service's primary domain. |

#### Example Request (`curl`)

```bash
curl -X DELETE "https://shorter.example.com/api/v1/links" \
-H "Authorization: Bearer YOUR_API_KEY_HERE" \
-H "Content-Type: application/json" \
-d '{
  "key": "my-api-link",
  "domain": "shorter.example.com"
}'
```

#### Example Success Response (`204 No Content`)

The server will respond with an empty body and a `204 No Content` status code on success.