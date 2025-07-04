export interface KeychainApp {
  id: number;
  account_id: string;
  account_secret: string;
  app_name: string;
  active: boolean;
  encrypt_type: 'default' | 'passphrase' | 'public_key';
  encrypt_public_key: number | null;
  created_at: Date;
  modified_at: Date;
}

export interface KeychainAppPublicKey {
  id: number;
  status: 'active' | 'previous_key' | 'deleted';
  app_id: number;
  key_name: string;
  key: string;
  created_at: Date;
  modified_at: Date;
}

export interface KeychainAppPrivateKey {
  id: number;
  app_id: number;
  retrieval_id: string;
  private_key: string;
  created_at: Date;
  modified_at: Date;
}

// Request/Response interfaces
export interface CreateKeychainAppRequest {
  account_id: string;
  account_secret: string;
  app_name: string;
  encrypt_type?: 'default' | 'passphrase' | 'public_key';
  encrypt_public_key?: number;
}

export interface UpdateKeychainAppRequest {
  app_name?: string;
  active?: boolean;
  // Note: encrypt_type is intentionally removed - cannot be modified after creation
  encrypt_public_key?: number;
}

export interface CreatePublicKeyRequest {
  key_name: string;
  key: string;
}

export interface UpdatePublicKeyRequest {
  status?: 'active' | 'previous_key' | 'deleted';
  key_name?: string;
  key?: string;
}

export interface StorePrivateKeyRequest {
  retrieval_id: string;
  private_key: string;
  passphrase?: string; // Required when app encrypt_type is 'passphrase'
}

export interface GetPrivateKeyRequest {
  passphrase?: string; // Required when app encrypt_type is 'passphrase'
}

export interface KeychainAppResponse {
  id: number;
  account_id: string;
  app_name: string;
  active: boolean;
  encrypt_type: string;
  encrypt_public_key: number | null;
  created_at: Date;
  modified_at: Date;
}

export interface PublicKeyResponse {
  id: number;
  status: string;
  app_id: number;
  key_name: string;
  key: string;
  created_at: Date;
  modified_at: Date;
}

export interface PrivateKeyResponse {
  retrieval_id: string;
  private_key: string;
  created_at: Date;
}