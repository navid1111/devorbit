import mongoose, { Types } from 'mongoose';
import { RedisClientType, createClient } from 'redis';
import { PermissionScope } from '../../modules/permission/permission.model';

class PermissionCacheService {
  private client: RedisClientType | null = null;
  private connectPromise: Promise<void> | null = null;
  private readonly ttlSeconds: number;
  private readonly enabled: boolean;

  constructor() {
    const parsedTtl = Number(process.env.PERMISSION_CACHE_TTL_SECONDS ?? '300');
    this.ttlSeconds = Number.isFinite(parsedTtl) && parsedTtl > 0 ? parsedTtl : 300;
    this.enabled = process.env.REDIS_ENABLED !== 'false';
  }

  private getRedisUrl(): string {
    return process.env.REDIS_URL ?? 'redis://localhost:6379';
  }

  private async ensureConnectedClient(): Promise<RedisClientType | null> {
    if (!this.enabled) {
      return null;
    }

    if (this.client?.isOpen) {
      return this.client;
    }

    if (!this.client) {
      this.client = createClient({ url: this.getRedisUrl() });
      this.client.on('error', error => {
        console.error('Redis client error:', error);
      });
    }

    if (!this.connectPromise) {
      this.connectPromise = this.client
        .connect()
        .then(() => undefined)
        .finally(() => {
          this.connectPromise = null;
        });
    }

    try {
      await this.connectPromise;
      return this.client;
    } catch (error) {
      console.error('Failed to connect Redis, falling back to DB checks:', error);
      return null;
    }
  }

  private buildPermissionKey(
    userId: Types.ObjectId,
    scope: PermissionScope,
    contextId?: Types.ObjectId,
  ): string {
    const userIdStr = userId.toString();
    const contextPart =
      scope === PermissionScope.GLOBAL ? 'global' : contextId?.toString() ?? 'none';

    return `perms:${scope}:${contextPart}:${userIdStr}`;
  }

  public async getPermissionIds(
    userId: Types.ObjectId,
    scope: PermissionScope,
    contextId?: Types.ObjectId,
  ): Promise<string[] | null> {
    const client = await this.ensureConnectedClient();
    if (!client) {
      return null;
    }

    const key = this.buildPermissionKey(userId, scope, contextId);
    const cached = await client.get(key);
    if (!cached) {
      return null;
    }

    try {
      const parsed = JSON.parse(cached) as string[];
      return Array.isArray(parsed) ? parsed : null;
    } catch (error) {
      // If cache value is malformed, ignore it and continue with DB query path.
      return null;
    }
  }

  public async setPermissionIds(
    userId: Types.ObjectId,
    scope: PermissionScope,
    permissionIds: string[],
    contextId?: Types.ObjectId,
  ): Promise<void> {
    const client = await this.ensureConnectedClient();
    if (!client) {
      return;
    }

    const key = this.buildPermissionKey(userId, scope, contextId);
    await client.set(key, JSON.stringify(permissionIds), {
      EX: this.ttlSeconds,
    });
  }

  public async invalidateForUser(
    userId: Types.ObjectId,
    scope: PermissionScope,
    contextId?: Types.ObjectId,
  ): Promise<void> {
    const client = await this.ensureConnectedClient();
    if (!client) {
      return;
    }

    const key = this.buildPermissionKey(userId, scope, contextId);
    await client.del(key);
  }

  public async invalidateForUsers(
    userIds: Types.ObjectId[],
    scope: PermissionScope,
    contextId?: Types.ObjectId,
  ): Promise<void> {
    if (userIds.length === 0) {
      return;
    }

    const client = await this.ensureConnectedClient();
    if (!client) {
      return;
    }

    const keys = Array.from(
      new Set(userIds.map(userId => this.buildPermissionKey(userId, scope, contextId))),
    );

    if (keys.length > 0) {
      await client.del(keys);
    }
  }
}

export const permissionCacheService = new PermissionCacheService();
