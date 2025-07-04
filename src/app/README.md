# Keychain Application

A secure cryptographic key management system built on the TypeScript API Framework. This application provides encrypted storage and management of public/private key pairs with multi-application support and user-based access control.

## 🔐 Overview

The Keychain Application is designed to securely store and manage cryptographic keys for multiple applications with comprehensive user access control. It provides:

- **Multi-tenant architecture** - Each application has its own isolated keychain
- **User-based access control** - Role-based permissions (owner, admin, viewer)
- **Multiple encryption methods** - Default, passphrase, and public key encryption
- **Public key versioning** - Support for key rotation with status tracking
- **Secure authentication** - Application-level and user-level authentication
- **Database flexibility** - Works with both MySQL and PostgreSQL (Supabase)
- **Web interface** - Complete dashboard for managing applications and keys
- **Dynamic form handling** - Adaptive UI based on encryption method selection
- **SSH key generation** - Built-in SSH key pair generation service
- **Comprehensive logging** - All API requests and responses are logged and encrypted

## 🏗️ Architecture

### Core Components

- **Keychain Apps** - Individual application containers for key management
- **User Access Control** - Role-based permissions linking users to applications
- **Public Keys** - Versioned public keys with status tracking (active/previous/deleted)
- **Private Keys** - Encrypted private keys with unique retrieval IDs
- **Authentication** - Dual-layer authentication (user + application)
- **SSH Key Generation** - Generate RSA and Ed25519 SSH key pairs
- **API Request Logging** - Comprehensive audit trail of all operations

### Security Features

- **Password Hashing** - bcrypt with salt for application secrets
- **Multiple Encryption Methods** - AES-CBC, RSA, and passphrase-based encryption
- **Access Control** - User-level and application-level isolation
- **Key Rotation** - Support for updating keys while maintaining history
- **Audit Logging** - Complete logging of all key operations with encryption
- **Sensitive Data Redaction** - Automatic redaction of sensitive information in logs

### Encryption Methods

1. **Default** - Common encryption key managed by the system (server-side encryption)
2. **Passphrase** - User must provide passphrase with each storage/retrieval operation
3. **Public Key** - Retrieved values remain encrypted with user's public key (end-to-end encryption)

## 🌐 Web Interface

### Landing Page (`/`)
- **Modern Design** - Gradient background with glassmorphism effects
- **Feature Showcase** - Highlights key capabilities
- **Secure Login** - JWT-based authentication modal
- **Responsive** - Mobile-friendly design

### Dashboard (`/dashboard`)
- **Application Management** - Create, edit, and manage keychain applications
- **Role-based UI** - Different actions available based on user permissions
- **Real-time Updates** - Dynamic loading without page refresh
- **Encryption Options** - Visual selection of encryption methods with dynamic form fields
- **Public Key Input** - Text area appears when selecting public key encryption method
- **Validation** - Real-time form validation with user-friendly error messages

## 📡 API Endpoints

### Authentication

#### Authenticate Application
```http
POST /api/keychain/authenticate
```

Authenticate a keychain application using account credentials (no user auth required).

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

### SSH Key Generation

#### Generate SSH Key Pair
```http
POST /api/ssh-keys/generate/{keyType}
Authorization: Bearer <jwt_token>
```

Generate an SSH key pair of the specified type.

**Path Parameters:**
- `keyType`: One of `RSA2048`, `RSA4096`, or `Ed25519`

**Response:**
```json
{
  "success": true,
  "data": {
    "publicKey": "ssh-rsa AAAAB3NzaC1yc2EAAAA...",
    "privateKey": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
    "keyType": "RSA2048",
    "fingerprint": "SHA256:..."
  },
  "message": "SSH RSA2048 key pair generated successfully"
}
```

**Supported Key Types:**
- **RSA2048** - 2048-bit RSA keys (good balance of security and performance)
- **RSA4096** - 4096-bit RSA keys (higher security, slower performance)
- **Ed25519** - Modern elliptic curve keys (recommended for new deployments)

---

### Application Management

#### Get User's Applications
```http
GET /api/keychain/apps
Authorization: Bearer <jwt_token>
```

Get all keychain applications the authenticated user has access to.

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": "number",
      "account_id": "string",
      "app_name": "string",
      "active": "boolean",
      "encrypt_type": "default|passphrase|public_key",
      "encrypt_public_key": "number|null",
      "created_at": "datetime",
      "modified_at": "datetime",
      "role": "owner|admin|viewer"
    }
  ]
}
```

#### Create Keychain Application
```http
POST /api/keychain/apps
Authorization: Bearer <jwt_token>
```

Create a new keychain application. The authenticated user becomes the owner.

**Request Body:**
```json
{
  "account_id": "string",
  "account_secret": "string",
  "app_name": "string",
  "encrypt_type": "default|passphrase|public_key",
  "public_key": "string (required if encrypt_type is public_key)"
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

Retrieve keychain application details (user must have access).

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
    "modified_at": "datetime",
    "role": "owner|admin|viewer"
  }
}
```

#### Update Keychain Application
```http
PUT /api/keychain/apps/{account_id}
Authorization: Bearer <jwt_token>
```

Update keychain application settings (requires owner or admin role).

**Request Body:**
```json
{
  "app_name": "string",
  "active": "boolean",
  "encrypt_public_key": "number|null"
}
```

**Note:** `encrypt_type` cannot be modified after creation for security reasons.

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

Retrieve public keys for an application (user must have access).

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

Store an encrypted private key with a unique retrieval ID. Encryption method depends on the application's `encrypt_type` setting.

**Request Body:**
```json
{
  "retrieval_id": "string",
  "private_key": "string",
  "passphrase": "string (required if app encrypt_type is 'passphrase')"
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
POST /api/keychain/apps/{account_id}/private-keys/{retrieval_id}/retrieve
Authorization: Bearer <jwt_token>
```

Retrieve and decrypt a private key. Decryption method depends on the application's `encrypt_type` setting.

**Request Body:**
```json
{
  "passphrase": "string (required if app encrypt_type is 'passphrase')"
}
```

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

**Note:** For `public_key` encryption type, the `private_key` field contains encrypted data that must be decrypted client-side.

#### List Private Keys
```http
GET /api/keychain/apps/{account_id}/private-keys
Authorization: Bearer <jwt_token>
```

List all private key retrieval IDs (without the actual keys, user must have access).

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

### 1. Generate SSH Keys

```bash
# Generate RSA2048 key pair
curl -X POST http://localhost:3000/api/ssh-keys/generate/RSA2048 \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json"

# Generate Ed25519 key pair
curl -X POST http://localhost:3000/api/ssh-keys/generate/Ed25519 \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json"

# Generate RSA4096 key pair
curl -X POST http://localhost:3000/api/ssh-keys/generate/RSA4096 \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json"
```

### 2. Setting Up a New Application via Web Interface

1. **Login** to the dashboard at `/dashboard`
2. **Click "Create New App"** button
3. **Fill in the form:**
   - Account ID: `myapp_001`
   - Account Secret: `secure_password_123`
   - Application Name: `My Application`
   - Encryption Method: Select desired method
   - Public Key: (text area appears if selecting public key encryption)
4. **Click "Create Application"**

### 3. Setting Up via API

```bash
# 1. Register and login to get JWT token
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123",
    "name": "John Doe"
  }'

curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123"
  }'

# 2. Generate SSH keys for the application
curl -X POST http://localhost:3000/api/ssh-keys/generate/RSA2048 \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json"

# 3. Create a keychain application with public key encryption
curl -X POST http://localhost:3000/api/keychain/apps \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "account_id": "myapp_001",
    "account_secret": "secure_password_123",
    "app_name": "My Application",
    "encrypt_type": "public_key",
    "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
  }'

# 4. Store a private key (will be encrypted with the public key)
curl -X POST http://localhost:3000/api/keychain/apps/myapp_001/private-keys \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "retrieval_id": "key_001",
    "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
  }'
```

### 4. Application Authentication (for external apps)

```bash
# Authenticate your application
curl -X POST http://localhost:3000/api/keychain/authenticate \
  -H "Content-Type: application/json" \
  -d '{
    "account_id": "myapp_001",
    "account_secret": "secure_password_123"
  }'
```

### 5. Key Operations with Different Encryption Methods

#### Default Encryption
```bash
# Store private key (default encryption)
curl -X POST http://localhost:3000/api/keychain/apps/myapp_default/private-keys \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "retrieval_id": "key_001",
    "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
  }'

# Retrieve private key (default encryption)
curl -X POST http://localhost:3000/api/keychain/apps/myapp_default/private-keys/key_001/retrieve \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json"
```

#### Passphrase Encryption
```bash
# Store private key with passphrase
curl -X POST http://localhost:3000/api/keychain/apps/myapp_passphrase/private-keys \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "retrieval_id": "key_001",
    "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
    "passphrase": "my-secure-passphrase"
  }'

# Retrieve private key with passphrase
curl -X POST http://localhost:3000/api/keychain/apps/myapp_passphrase/private-keys/key_001/retrieve \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "passphrase": "my-secure-passphrase"
  }'
```

#### Public Key Encryption
```bash
# Store private key (encrypted with app's public key)
curl -X POST http://localhost:3000/api/keychain/apps/myapp_publickey/private-keys \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "retrieval_id": "key_001",
    "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
  }'

# Retrieve private key (returns encrypted data for client-side decryption)
curl -X POST http://localhost:3000/api/keychain/apps/myapp_publickey/private-keys/key_001/retrieve \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json"
```

## 🛡️ Security Considerations

### Encryption Methods Comparison

| Method | Server Access | Use Case | Security Level |
|--------|---------------|----------|----------------|
| **Default** | Server can decrypt | Automated processes, convenience | Good |
| **Passphrase** | Server cannot decrypt without passphrase | User-controlled encryption | Better |
| **Public Key** | Server cannot decrypt at all | End-to-end encryption | Best |

### SSH Key Security
- **Key Type Selection** - Ed25519 recommended for new deployments
- **Key Storage** - Store generated keys securely
- **Key Rotation** - Regularly generate new SSH keys
- **Access Control** - Only authenticated users can generate keys

### API Request Logging
- **Comprehensive Audit Trail** - All API requests and responses are logged
- **Sensitive Data Protection** - Passwords, tokens, and private keys are automatically redacted
- **Encrypted Storage** - All log data is encrypted using the master encryption key
- **User Tracking** - User IDs are extracted from JWT tokens for accountability

### Access Control
- **User authentication** required for all management operations
- **Role-based permissions** control what users can do
- **Application isolation** ensures users can only access their applications
- **Inactive applications** cannot store or retrieve keys

### Best Practices
1. **Choose appropriate encryption method** based on your security requirements
2. **Use Ed25519 keys** for new SSH deployments when possible
3. **Rotate keys regularly** - Use the public key versioning system
4. **Secure storage** - Keep retrieval IDs secure and unique
5. **Environment variables** - Never hardcode secrets in your application
6. **HTTPS only** - Always use HTTPS in production
7. **Monitor logs** - Review API request logs for suspicious activity
8. **Role management** - Grant minimum necessary permissions

## 🗄️ Database Schema

### keychain_apps
- `id` - Primary key
- `account_id` - Unique application identifier
- `account_secret` - Hashed application secret
- `app_name` - Human-readable application name
- `active` - Application status
- `encrypt_type` - Encryption method preference (cannot be changed after creation)
- `encrypt_public_key` - Reference to encryption public key

### user_keychain_apps
- `id` - Primary key
- `user_id` - Foreign key to users table
- `keychain_app_id` - Foreign key to keychain_apps table
- `role` - User role (owner/admin/viewer)

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

### api_request_logs
- `id` - Primary key
- `request_uuid` - Unique identifier for each request
- `user_id` - Foreign key to users table (nullable)
- `method` - HTTP method
- `url` - Request URL
- `status_code` - HTTP response status
- `encrypted_headers` - Encrypted request headers
- `encrypted_request_body` - Encrypted request body
- `encrypted_response_body` - Encrypted response body
- `ip_address` - Client IP address
- `user_agent` - Client User-Agent string
- `response_time_ms` - Response time in milliseconds
- `error_message` - Error message (if any)
- `created_at` - Timestamp

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

  async generateSSHKeys(keyType = 'RSA2048') {
    const response = await axios.post(
      `${this.baseUrl}/api/ssh-keys/generate/${keyType}`,
      {},
      { headers: this.headers }
    );
    return response.data.data;
  }

  async createApp(accountId, accountSecret, appName, encryptType = 'default', publicKey = null) {
    const data = {
      account_id: accountId,
      account_secret: accountSecret,
      app_name: appName,
      encrypt_type: encryptType
    };

    if (encryptType === 'public_key' && publicKey) {
      data.public_key = publicKey;
    }

    const response = await axios.post(`${this.baseUrl}/api/keychain/apps`, data, { headers: this.headers });
    return response.data;
  }

  async getUserApps() {
    const response = await axios.get(`${this.baseUrl}/api/keychain/apps`, { headers: this.headers });
    return response.data;
  }

  async storePrivateKey(accountId, retrievalId, privateKey, passphrase = null) {
    const data = { retrieval_id: retrievalId, private_key: privateKey };
    if (passphrase) {
      data.passphrase = passphrase;
    }

    const response = await axios.post(
      `${this.baseUrl}/api/keychain/apps/${accountId}/private-keys`,
      data,
      { headers: this.headers }
    );
    return response.data;
  }

  async getPrivateKey(accountId, retrievalId, passphrase = null) {
    const data = {};
    if (passphrase) {
      data.passphrase = passphrase;
    }

    const response = await axios.post(
      `${this.baseUrl}/api/keychain/apps/${accountId}/private-keys/${retrievalId}/retrieve`,
      data,
      { headers: this.headers }
    );
    return response.data.data.private_key;
  }
}

// Usage
const client = new KeychainClient('http://localhost:3000', 'your-jwt-token');

// Generate SSH keys
const sshKeys = await client.generateSSHKeys('Ed25519');
console.log('Generated SSH keys:', sshKeys);

// Create application with generated public key
const app = await client.createApp(
  'myapp_001',
  'secure_password',
  'My Application',
  'public_key',
  sshKeys.publicKey
);
```

## 📝 Error Handling

### Common Error Codes

- **400 Bad Request** - Invalid request parameters, missing required fields, or missing passphrase
- **401 Unauthorized** - Invalid or missing authentication, or invalid passphrase
- **403 Forbidden** - Insufficient permissions for the requested operation
- **404 Not Found** - Application or key not found, or user doesn't have access
- **500 Internal Server Error** - Server-side error

### Error Response Format

```json
{
  "success": false,
  "error": "Error message description"
}
```

## 🔄 Key Rotation Workflow

1. **Generate new key pair** using the SSH key generation endpoint or your application
2. **Add new public key** via API or dashboard (automatically marks old as previous)
3. **Store new private key** with new retrieval ID
4. **Update application** to use new keys
5. **Keep old keys** for backward compatibility if needed
6. **Mark old keys as deleted** when no longer needed

## 👥 User Management

### Roles and Permissions

- **Owner**
  - Full control over the application
  - Can modify all settings
  - Can manage user access
  - Can delete the application

- **Admin**
  - Can modify application settings (except encryption type)
  - Can manage keys
  - Can view all application data
  - Cannot delete the application

- **Viewer**
  - Read-only access to application data
  - Can view public keys
  - Can list private key IDs (but not retrieve actual keys)
  - Cannot modify anything

### Access Control Flow

1. **User Authentication** - JWT token validates user identity
2. **Application Access Check** - Verify user has access to the application
3. **Role Permission Check** - Ensure user's role allows the requested operation
4. **Operation Execution** - Perform the requested action with full audit logging

## 📊 Monitoring and Maintenance

### Health Checks
- Monitor application status via `/api/health`
- Check database connectivity
- Verify encryption/decryption operations

### Audit and Compliance
- **Request Logging** - All API requests are logged with encrypted storage
- **User Activity Tracking** - User IDs are tracked for all operations
- **Sensitive Data Protection** - Automatic redaction of sensitive information
- **Performance Monitoring** - Response times are tracked for all requests

### Backup Considerations
- **Database backups** - Regular encrypted backups including audit logs
- **Key recovery** - Secure backup of master encryption key
- **Application secrets** - Secure storage of account credentials
- **Log retention** - Configure appropriate log retention policies

### Audit Logging
- All key operations are logged with user information and encryption method
- SSH key generation events are tracked
- Application access attempts are recorded
- Failed authentication attempts are logged
- Key rotation events are documented
- API request/response data is encrypted and stored

---

## 🤝 Support

For issues, questions, or contributions related to the Keychain Application, please refer to the main project documentation or create an issue in the project repository.

The Keychain Application demonstrates the full capabilities of the TypeScript API Framework and serves as a complete example of building secure, multi-tenant applications with user access control, multiple encryption methods, SSH key generation, and comprehensive audit logging.