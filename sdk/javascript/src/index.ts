/**
 * GM-KMS JavaScript/TypeScript SDK
 *
 * @example
 * ```typescript
 * import { Client, KeySpec } from '@gm-kms/sdk';
 *
 * const client = new Client({
 *   serverUrl: 'http://localhost:8080',
 *   apiKey: 'your-api-key',
 *   tenantId: 'tenant-1',
 * });
 *
 * // Create a key
 * const key = await client.createKey({
 *   name: 'my-key',
 *   spec: KeySpec.AES_256_GCM,
 * });
 *
 * // Encrypt
 * const result = await client.encrypt({
 *   keyId: key.id,
 *   plaintext: Buffer.from('secret data'),
 * });
 *
 * // Decrypt
 * const plaintext = await client.decrypt({
 *   keyId: key.id,
 *   ciphertext: result.ciphertext,
 *   nonce: result.nonce,
 *   tag: result.tag,
 * });
 * ```
 */

export enum KeySpec {
  AES_256_GCM = 'aes-256-gcm',
  SM4 = 'sm4',
  ED25519 = 'ed25519',
  SM2 = 'sm2',
  ECDSA_P256 = 'ecdsa-p256',
  ECDSA_P384 = 'ecdsa-p384',
  HMAC_SHA256 = 'hmac-sha256',
}

export interface KeyMeta {
  id: string;
  name: string;
  spec: KeySpec;
  status: string;
  version: number;
  tenant_id: string;
  created_at: string;
  rotated_at?: string;
  description?: string;
}

export interface CreateKeyRequest {
  name: string;
  spec: KeySpec;
  tenant_id?: string;
  description?: string;
  metadata?: {
    tags?: string[];
    labels?: Record<string, string>;
  };
}

export interface EncryptResult {
  key_id: string;
  version: number;
  ciphertext: string;
  nonce: string;
  tag: string;
}

export interface EncryptRequest {
  keyId: string;
  plaintext: Buffer;
  aad?: Buffer;
}

export interface DecryptRequest {
  keyId: string;
  ciphertext: string;
  nonce: string;
  tag: string;
}

export interface SignResult {
  key_id: string;
  version: number;
  signature: string;
}

export interface SignRequest {
  keyId: string;
  data: Buffer;
}

export interface VerifyRequest {
  keyId: string;
  data: Buffer;
  signature: string;
}

export interface VerifyResult {
  valid: boolean;
}

export interface HealthResult {
  status: string;
}

export class Error extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'KmsError';
  }
}

export interface ClientOptions {
  serverUrl: string;
  apiKey?: string;
  tenantId?: string;
  timeout?: number;
}

export class Client {
  private serverUrl: string;
  private apiKey?: string;
  private tenantId: string;
  private timeout: number;

  constructor(options: ClientOptions) {
    this.serverUrl = options.serverUrl.replace(/\/$/, '');
    this.apiKey = options.apiKey;
    this.tenantId = options.tenantId || 'default';
    this.timeout = options.timeout || 30000;
  }

  private async request<T>(
    method: string,
    path: string,
    body?: Record<string, unknown>,
    tenantId?: string
  ): Promise<T> {
    const url = `${this.serverUrl}${path}`;
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };

    if (this.apiKey) {
      headers['Authorization'] = `Bearer ${this.apiKey}`;
    }

    const requestBody = body ? JSON.stringify(body) : undefined;

    try {
      const response = await fetch(url, {
        method,
        headers,
        body: requestBody,
        signal: AbortSignal.timeout(this.timeout),
      });

      if (!response.ok) {
        const errorBody = await response.text();
        try {
          const errorData = JSON.parse(errorBody);
          throw new Error(errorData.error || `HTTP ${response.status}: ${errorBody}`);
        } catch (e) {
          if (e instanceof Error) throw e;
          throw new Error(`HTTP ${response.status}: ${errorBody}`);
        }
      }

      return response.json();
    } catch (e) {
      if (e instanceof Error) throw e;
      throw new Error(`Connection error: ${e}`);
    }
  }

  private base64Encode(buffer: Buffer): string {
    return buffer.toString('base64');
  }

  private base64Decode(base64: string): Buffer {
    return Buffer.from(base64, 'base64');
  }

  async createKey(request: CreateKeyRequest): Promise<KeyMeta> {
    const tid = request.tenant_id || this.tenantId;
    const body: Record<string, unknown> = {
      name: request.name,
      spec: request.spec,
      tenant_id: tid,
    };
    if (request.description) {
      body.description = request.description;
    }
    if (request.metadata) {
      body.metadata = request.metadata;
    }

    const result = await this.request<any>('POST', '/v1/keys', body);
    return this.parseKeyMeta(result);
  }

  async getKey(keyId: string): Promise<KeyMeta> {
    const result = await this.request<any>('GET', `/v1/keys/${keyId}`);
    return this.parseKeyMeta(result);
  }

  async listKeys(tenantId?: string): Promise<KeyMeta[]> {
    const tid = tenantId || this.tenantId;
    const result = await this.request<any[]>('GET', `/v1/keys?tenant_id=${tid}`);
    return result.map((r) => this.parseKeyMeta(r));
  }

  async encrypt(request: EncryptRequest): Promise<EncryptResult> {
    const plaintextB64 = this.base64Encode(request.plaintext);
    const body: Record<string, unknown> = { plaintext: plaintextB64 };
    if (request.aad) {
      body.aad = this.base64Encode(request.aad);
    }

    const result = await this.request<EncryptResult>(
      'POST',
      `/v1/keys/${request.keyId}/encrypt`,
      body
    );
    return result;
  }

  async decrypt(request: DecryptRequest): Promise<Buffer> {
    const body = {
      ciphertext: request.ciphertext,
      nonce: request.nonce,
      tag: request.tag,
    };

    const result = await this.request<{ plaintext: string }>(
      'POST',
      `/v1/keys/${request.keyId}/decrypt`,
      body
    );

    return this.base64Decode(result.plaintext);
  }

  async sign(request: SignRequest): Promise<SignResult> {
    const dataB64 = this.base64Encode(request.data);
    const body = { data: dataB64 };

    const result = await this.request<SignResult>(
      'POST',
      `/v1/keys/${request.keyId}/sign`,
      body
    );
    return result;
  }

  async verify(request: VerifyRequest): Promise<VerifyResult> {
    const dataB64 = this.base64Encode(request.data);
    const body = { data: dataB64, signature: request.signature };

    const result = await this.request<VerifyResult>(
      'POST',
      `/v1/keys/${request.keyId}/verify`,
      body
    );
    return result;
  }

  async rotateKey(keyId: string): Promise<KeyMeta> {
    const result = await this.request<any>('POST', `/v1/keys/${keyId}/rotate`);
    return this.parseKeyMeta(result);
  }

  async deleteKey(keyId: string): Promise<void> {
    await this.request('DELETE', `/v1/keys/${keyId}`);
  }

  async health(): Promise<string> {
    const result = await this.request<HealthResult>('GET', '/v1/health');
    return result.status;
  }

  private parseKeyMeta(data: any): KeyMeta {
    return {
      id: data.id,
      name: data.name,
      spec: data.spec || data.key_spec || KeySpec.AES_256_GCM,
      status: data.status,
      version: data.version,
      tenant_id: data.tenant_id,
      created_at: data.created_at,
      rotated_at: data.rotated_at,
      description: data.description,
    };
  }
}
