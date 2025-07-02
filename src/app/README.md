# Keychain Application

A secure cryptographic key management system built on the TypeScript API Framework. This application provides encrypted storage and management of public/private key pairs with multi-application support and user-based access control.

## 🔐 Overview

The Keychain Application is designed to securely store and manage cryptographic keys for multiple applications with comprehensive user access control. It provides:

- **Multi-tenant architecture** - Each application has its own isolated keychain
- **User-based access control** - Role-based permissions (owner, admin, viewer)
- **Encrypted storage** - All private keys are encrypted using AES-CBC encryption
- **Public key versioning** - Support for key rotation with status tracking
- **Multiple encryption methods** - Default, passphrase, and public key encryption
- **Secure authentication** - Application-level and user-level authentication
- **Database flexibility** - Works with both MySQL and PostgreSQL (Supabase)
- **Web interface** - Complete dashboard for managing applications and keys

## 🏗️ Architecture

### Core Components

- **Keychain Apps** - Individual application containers for key management
- **User Access Control** - Role-based permissions linking users to applications
- **Public Keys** - Versioned public keys with status tracking (active/previous/deleted)
- **Private Keys** - Encrypted private keys with unique retrieval IDs
- **Authentication** - Dual-layer authentication (user + application)

### Security Features

- **Password Hashing** - bcrypt with salt for application secrets
- **Data Encryption** - AES-CBC encryption for all private keys
- **Access Control** - User-level and application-level isolation
- **Key Rotation** - Support for updating keys while maintaining history
- **Audit Logging** - Complete logging of all key operations

### Encryption Methods

1. **Default** - Common encryption key managed by the system
2. **Passphrase** - User must provide passphrase with each retrieval
3. **Public Key** - Retrieved values remain encrypted with user's public key

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
- **Encryption Options** - Visual selection of encryption methods
- **Public Key Input** - Dynamic form fields based on encryption selection

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
      "encrypt_type": "string",
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

Store an encrypted private key with a unique retrieval ID (user must have access).

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

Retrieve and decrypt a private key (user must have access).

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

### 1. Setting Up a New Application via Web Interface

1. **Login** to the dashboard at `/dashboard`
2. **Click "Create New App"** button
3. **Fill in the form:**
   - Account ID: `myapp_001`
   - Account Secret: `secure_password_123`
   - Application Name: `My Application`
   - Encryption Method: Select desired method
   - Public Key: (if using public key encryption)
4. **Click "Create Application"**

### 2. Setting Up via API

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

# 2. Create a keychain application
curl -X POST http://localhost:3000/api/keychain/apps \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "account_id": "myapp_001",
    "account_secret": "secure_password_123",
    "app_name": "My Application",
    "encrypt_type": "default"
  }'

# 3. Add a public key
curl -X POST http://localhost:3000/api/keychain/apps/myapp_001/public-keys \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "key_name": "primary_key",
    "key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
  }'

# 4. Store a private key
curl -X POST http://localhost:3000/api/keychain/apps/myapp_001/private-keys \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "retrieval_id": "key_001",
    "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
  }'
```

### 3. Application Authentication (for external apps)

```bash
# Authenticate your application
curl -X POST http://localhost:3000/api/keychain/authenticate \
  -H "Content-Type: application/json" \
  -d '{
    "account_id": "myapp_001",
    "account_secret": "secure_password_123"
  }'
```

### 4. Key Retrieval

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
- **Public key encryption** option allows end-to-end encryption

### Access Control
- **User authentication** required for all management operations
- **Role-based permissions** control what users can do
- **Application isolation** ensures users can only access their applications
- **Inactive applications** cannot store or retrieve keys

### Best Practices
1. **Rotate keys regularly** - Use the public key versioning system
2. **Secure storage** - Keep retrieval IDs secure and unique
3. **Environment variables** - Never hardcode secrets in your application
4. **HTTPS only** - Always use HTTPS in production
5. **Audit logs** - Monitor key access patterns
6. **Role management** - Grant minimum necessary permissions

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

- **400 Bad Request** - Invalid request parameters or missing required fields
- **401 Unauthorized** - Invalid or missing authentication
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

1. **Generate new key pair** in your application
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

### Backup Considerations
- **Database backups** - Regular encrypted backups
- **Key recovery** - Secure backup of master encryption key
- **Application secrets** - Secure storage of account credentials

### Audit Logging
- All key operations are logged with user information
- Application access attempts are tracked
- Failed authentication attempts are recorded
- Key rotation events are documented

---

## 🤝 Support

For issues, questions, or contributions related to the Keychain Application, please refer to the main project documentation or create an issue in the project repository.

The Keychain Application demonstrates the full capabilities of the TypeScript API Framework and serves as a complete example of building secure, multi-tenant applications with user access control.