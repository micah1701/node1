# Keychain Application

A secure cryptographic key management system built on the TypeScript API Framework. This application provides encrypted storage and management of public/private key pairs with multi-application support.

## 🔐 Overview

The Keychain Application is designed to securely store and manage cryptographic keys for multiple applications. It provides:

- **Multi-tenant architecture** - Each application has its own isolated keychain
- **Encrypted storage** - All private keys are encrypted using AES-CBC encryption
- **Public key versioning** - Support for key rotation with status tracking
- **Secure authentication** - Application-level authentication with hashed secrets
- **Database flexibility** - Works with both MySQL and PostgreSQL (Supabase)

## 🏗️ Architecture

### Core Components

- **Keychain Apps** - Individual application containers for key management
- **Public Keys** - Versioned public keys with status tracking (active/previous/deleted)
- **Private Keys** - Encrypted private keys with unique retrieval IDs
- **Authentication** - Secure app-level authentication system

### Security Features

- **Password Hashing** - bcrypt with salt for application secrets
- **Data Encryption** - AES-CBC encryption for all private keys
- **Access Control** - Application-level isolation and authentication
- **Key Rotation** - Support for updating keys while maintaining history

## 📡 API Endpoints

### Authentication

#### Authenticate Application
```http
POST /api/keychain/authenticate
```

Authenticate a keychain application using account credentials.

**Request Body:**
```json
{
  "account_id": "string",
  "account_secret": "string"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "account_id": "string",
    "app_name": "string"
  },
  "message": "Authentication successful"
}
```

---

### Application Management

#### Create Keychain Application
```http
POST /api/keychain/apps
Authorization: Bearer <jwt_token>
```

Create a new keychain application.

**Request Body:**
```json
{
  "account_id": "string",
  "account_secret": "string",
  "app_name": "string",
  "encrypt_type": "default|passphrase|public_key",
  "encrypt_public_key": "number|null"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "id": "number",
    "account_id": "string",
    "app_name": "string",
    "active": "boolean",
    "encrypt_type": "string",
    "encrypt_public_key": "number|null",
    "created_at": "datetime",
    "modified_at": "datetime"
  },
  "message": "Keychain application created successfully"
}
```

#### Get Keychain Application
```http
GET /api/keychain/apps/{account_id}
Authorization: Bearer <jwt_token>
```

Retrieve keychain application details.

**Response:**
```json
{
  "success": true,
  "data": {
    "id": "number",
    "account_id": "string",
    "app_name": "string",
    "active": "boolean",
    "encrypt_type": "string",
    "encrypt_public_key": "number|null",
    "created_at": "datetime",
    "modified_at": "datetime"
  }
}
```

#### Update Keychain Application
```http
PUT /api/keychain/apps/{account_id}
Authorization: Bearer <jwt_token>
```

Update keychain application settings.

**Request Body:**
```json
{
  "app_name": "string",
  "active": "boolean",
  "encrypt_type": "default|passphrase|public_key",
  "encrypt_public_key": "number|null"
}
```

---

### Public Key Management

#### Add Public Key
```http
POST /api/keychain/apps/{account_id}/public-keys
Authorization: Bearer <jwt_token>
```

Add a new public key to the application. This automatically marks previous active keys as "previous_key".

**Request Body:**
```json
{
  "key_name": "string",
  "key": "string"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "id": "number",
    "status": "active",
    "app_id": "number",
    "key_name": "string",
    "key": "string",
    "created_at": "datetime",
    "modified_at": "datetime"
  },
  "message": "Public key added successfully"
}
```

#### Get Public Keys
```http
GET /api/keychain/apps/{account_id}/public-keys?status=active
Authorization: Bearer <jwt_token>
```

Retrieve public keys for an application.

**Query Parameters:**
- `status` (optional): Filter by status (`active`, `previous_key`, `deleted`)

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": "number",
      "status": "string",
      "app_id": "number",
      "key_name": "string",
      "key": "string",
      "created_at": "datetime",
      "modified_at": "datetime"
    }
  ]
}
```

---

### Private Key Management

#### Store Private Key
```http
POST /api/keychain/apps/{account_id}/private-keys
Authorization: Bearer <jwt_token>
```

Store an encrypted private key with a unique retrieval ID.

**Request Body:**
```json
{
  "retrieval_id": "string",
  "private_key": "string"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "retrieval_id": "string"
  },
  "message": "Private key stored successfully"
}
```

#### Retrieve Private Key
```http
GET /api/keychain/apps/{account_id}/private-keys/{retrieval_id}
Authorization: Bearer <jwt_token>
```

Retrieve and decrypt a private key.

**Response:**
```json
{
  "success": true,
  "data": {
    "retrieval_id": "string",
    "private_key": "string",
    "created_at": "datetime"
  }
}
```

#### List Private Keys
```http
GET /api/keychain/apps/{account_id}/private-keys
Authorization: Bearer <jwt_token>
```

List all private key retrieval IDs (without the actual keys).

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "retrieval_id": "string",
      "created_at": "datetime",
      "modified_at": "datetime"
    }
  ]
}
```

## 🔧 Usage Examples

### 1. Setting Up a New Application

```bash
# 1. Create a keychain application
curl -X POST http://localhost:3000/api/keychain/apps \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "account_id": "myapp_001",
    "account_secret": "secure_password_123",
    "app_name": "My Application",
    "encrypt_type": "default"
  }'

# 2. Add a public key
curl -X POST http://localhost:3000/api/keychain/apps/myapp_001/public-keys \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "key_name": "primary_key",
    "key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
  }'

# 3. Store a private key
curl -X POST http://localhost:3000/api/keychain/apps/myapp_001/private-keys \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "retrieval_id": "key_001",
    "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
  }'
```

### 2. Application Authentication

```bash
# Authenticate your application
curl -X POST http://localhost:3000/api/keychain/authenticate \
  -H "Content-Type: application/json" \
  -d '{
    "account_id": "myapp_001",
    "account_secret": "secure_password_123"
  }'
```

### 3. Key Retrieval

```bash
# Get active public keys
curl -X GET http://localhost:3000/api/keychain/apps/myapp_001/public-keys?status=active \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# Retrieve a private key
curl -X GET http://localhost:3000/api/keychain/apps/myapp_001/private-keys/key_001 \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## 🛡️ Security Considerations

### Encryption
- **Private keys** are encrypted using AES-CBC with PBKDF2 key derivation
- **Application secrets** are hashed using bcrypt with salt
- **Master encryption key** must be securely configured in environment variables

### Access Control
- All endpoints (except authentication) require JWT authentication
- Applications can only access their own keys
- Inactive applications cannot store or retrieve keys

### Best Practices
1. **Rotate keys regularly** - Use the public key versioning system
2. **Secure storage** - Keep retrieval IDs secure and unique
3. **Environment variables** - Never hardcode secrets in your application
4. **HTTPS only** - Always use HTTPS in production
5. **Audit logs** - Monitor key access patterns

## 🗄️ Database Schema

### keychain_apps
- `id` - Primary key
- `account_id` - Unique application identifier
- `account_secret` - Hashed application secret
- `app_name` - Human-readable application name
- `active` - Application status
- `encrypt_type` - Encryption method preference
- `encrypt_public_key` - Reference to encryption public key

### keychain_app_public_keys
- `id` - Primary key
- `app_id` - Foreign key to keychain_apps
- `status` - Key status (active/previous_key/deleted)
- `key_name` - Human-readable key name
- `key` - Public key content

### keychain_app_private_keys
- `id` - Primary key
- `app_id` - Foreign key to keychain_apps
- `retrieval_id` - Unique identifier for key retrieval
- `private_key` - Encrypted private key content

## 🚀 Integration Guide

### Node.js Example

```javascript
const axios = require('axios');

class KeychainClient {
  constructor(baseUrl, jwtToken) {
    this.baseUrl = baseUrl;
    this.headers = {
      'Authorization': `Bearer ${jwtToken}`,
      'Content-Type': 'application/json'
    };
  }

  async createApp(accountId, accountSecret, appName) {
    const response = await axios.post(`${this.baseUrl}/api/keychain/apps`, {
      account_id: accountId,
      account_secret: accountSecret,
      app_name: appName
    }, { headers: this.headers });
    
    return response.data;
  }

  async storePrivateKey(accountId, retrievalId, privateKey) {
    const response = await axios.post(
      `${this.baseUrl}/api/keychain/apps/${accountId}/private-keys`,
      { retrieval_id: retrievalId, private_key: privateKey },
      { headers: this.headers }
    );
    
    return response.data;
  }

  async getPrivateKey(accountId, retrievalId) {
    const response = await axios.get(
      `${this.baseUrl}/api/keychain/apps/${accountId}/private-keys/${retrievalId}`,
      { headers: this.headers }
    );
    
    return response.data.data.private_key;
  }
}

// Usage
const client = new KeychainClient('http://localhost:3000', 'your-jwt-token');
```

## 📝 Error Handling

### Common Error Codes

- **400 Bad Request** - Invalid request parameters
- **401 Unauthorized** - Invalid or missing authentication
- **403 Forbidden** - Insufficient permissions
- **404 Not Found** - Application or key not found
- **500 Internal Server Error** - Server-side error

### Error Response Format

```json
{
  "success": false,
  "error": "Error message description"
}
```

## 🔄 Key Rotation Workflow

1. **Generate new key pair** in your application
2. **Add new public key** via API (automatically marks old as previous)
3. **Store new private key** with new retrieval ID
4. **Update application** to use new keys
5. **Keep old keys** for backward compatibility if needed
6. **Mark old keys as deleted** when no longer needed

## 📊 Monitoring and Maintenance

### Health Checks
- Monitor application status via `/api/health`
- Check database connectivity
- Verify encryption/decryption operations

### Backup Considerations
- **Database backups** - Regular encrypted backups
- **Key recovery** - Secure backup of master encryption key
- **Application secrets** - Secure storage of account credentials

---

## 🤝 Support

For issues, questions, or contributions related to the Keychain Application, please refer to the main project documentation or create an issue in the project repository.