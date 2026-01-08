import { Request, Response, NextFunction } from 'express';

export interface Identity {
  ip: string;
  userId: string;
  apiKey?: string;
  path: string;
  method: string;
}

export interface SecurityEvent {
  timestamp: string;
  ip: string;
  userId: string;
  path: string;
  method: string;
  statusCode: number;
  signals: string[];
  riskScore: number;
  action: 'ALLOW' | 'THROTTLE' | 'BAN';
}

export interface AbuseDetectorConfig {
  ipLimit: number;
  userLimit: number;
  windowMs: number;
  maxAuthFailures: number;
  banDuration: number;
  throttleScore: number;
  banScore: number;
  suspiciousPaths: string[];
}

export class AbuseDetector {
  private requestCounts = new Map<string, number[]>();
  private suspiciousActivity = new Map<string, number>();
  private bans = new Map<string, { reason: string; expiresAt: number }>();
  private config: AbuseDetectorConfig;

  constructor(config?: Partial<AbuseDetectorConfig>) {
    this.config = {
      ipLimit: 100,
      userLimit: 50,
      windowMs: 60_000,
      maxAuthFailures: 5,
      banDuration: 15 * 60_000,
      throttleScore: 50,
      banScore: 100,
      suspiciousPaths: ['/admin', '/api/auth', '/api/users'],
      ...config,
    };
  }

  /** Extract identity from request */
  extractIdentity(req: Request): Identity {
    return {
      ip: req.ip || req.connection.remoteAddress || 'unknown',
      userId: req.headers['x-user-id']?.toString() || 'anonymous',
      apiKey: req.headers['api-key']?.toString(),
      path: req.path,
      method: req.method,
    };
  }

  /** Check if identifier is banned */
  private isBanned(identifier: string): boolean {
    const ban = this.bans.get(identifier);
    if (!ban) return false;
    if (Date.now() > ban.expiresAt) {
      this.bans.delete(identifier);
      return false;
    }
    return true;
  }

  /** Record request timestamps and enforce basic rate limits */
  private recordRequest(identity: Identity): number {
    const now = Date.now();
    const windowStart = now - this.config.windowMs;
    let score = 0;

    // IP
    const ipKey = `ip:${identity.ip}`;
    if (!this.requestCounts.has(ipKey)) this.requestCounts.set(ipKey, []);
    const ipRequests = this.requestCounts.get(ipKey)!;
    while (ipRequests.length && ipRequests[0] < windowStart) ipRequests.shift();
    ipRequests.push(now);
    if (ipRequests.length > this.config.ipLimit) score += 50;

    // User
    if (identity.userId !== 'anonymous') {
      const userKey = `user:${identity.userId}`;
      if (!this.requestCounts.has(userKey)) this.requestCounts.set(userKey, []);
      const userRequests = this.requestCounts.get(userKey)!;
      while (userRequests.length && userRequests[0] < windowStart) userRequests.shift();
      userRequests.push(now);
      if (userRequests.length > this.config.userLimit) score += 50;
    }

    return score;
  }

  /** Detect suspicious behavior and update score */
  private detectSuspiciousBehavior(identity: Identity, statusCode: number): { signals: string[]; score: number } {
    const signals: string[] = [];
    let score = 0;

    // Auth failures
    if (identity.path.includes('/login') || identity.path.includes('/auth')) {
      if (statusCode === 401 || statusCode === 403) {
        const key = `auth_fail:${identity.ip}`;
        const count = (this.suspiciousActivity.get(key) || 0) + 1;
        this.suspiciousActivity.set(key, count);
        if (count >= this.config.maxAuthFailures) {
          signals.push('Multiple auth failures');
          score += 50;
        }
      }
    }

    // Suspicious paths
    if (this.config.suspiciousPaths.some(p => identity.path.includes(p))) {
      const key = `suspicious_path:${identity.ip}`;
      const count = (this.suspiciousActivity.get(key) || 0) + 1;
      this.suspiciousActivity.set(key, count);
      if (count > 3) {
        signals.push('Scanning sensitive paths');
        score += 25;
      }
    }

    return { signals, score };
  }

  /** Ban an identifier */
  private banIdentifier(identifier: string, reason: string) {
    this.bans.set(identifier, {
      reason,
      expiresAt: Date.now() + this.config.banDuration,
    });
    console.log(`[SECURITY] Banned ${identifier}: ${reason}`);
  }

  /** Main Express middleware */
  middleware() {
    return (req: Request, res: Response, next: NextFunction) => {
      const identity = this.extractIdentity(req);

      if (this.isBanned(identity.ip)) {
        return res.status(403).json({
          error: 'Access temporarily blocked',
          message: 'Too many suspicious activities',
        });
      }

      // Record requests and basic rate limit scoring
      let riskScore = this.recordRequest(identity);

      // After response, check status and suspicious behavior
      const originalSend = res.send.bind(res);
      res.send = (body: any) => {
        const statusCode = res.statusCode;
        const { signals, score } = this.detectSuspiciousBehavior(identity, statusCode);
        riskScore += score;

        // Decide action
        let action: 'ALLOW' | 'THROTTLE' | 'BAN' = 'ALLOW';
        if (riskScore >= this.config.banScore) {
          this.banIdentifier(identity.ip, signals.join(', ') || 'Risk threshold exceeded');
          action = 'BAN';
        } else if (riskScore >= this.config.throttleScore) {
          action = 'THROTTLE';
        }

        // Log security event
        const event: SecurityEvent = {
          timestamp: new Date().toISOString(),
          ip: identity.ip,
          userId: identity.userId,
          path: identity.path,
          method: identity.method,
          statusCode,
          signals,
          riskScore,
          action,
        };
        console.log('[SECURITY EVENT]', JSON.stringify(event, null, 2));

        return originalSend(body);
      };

      next();
    };
  }

  /** Periodic cleanup to remove old requests and expired bans */
  cleanup() {
    const now = Date.now();

    // Clean bans
    for (const [key, ban] of this.bans.entries()) {
      if (ban.expiresAt <= now) this.bans.delete(key);
    }

    // Clean request counts
    const cutoff = now - 2 * this.config.windowMs;
    for (const [key, timestamps] of this.requestCounts.entries()) {
      const filtered = timestamps.filter(t => t > cutoff);
      if (filtered.length) this.requestCounts.set(key, filtered);
      else this.requestCounts.delete(key);
    }

    // Clean suspicious activity (older than 1 hour)
    const activityCutoff = now - 60 * 60_000;
    for (const [key, count] of this.suspiciousActivity.entries()) {
      if (count < 0) this.suspiciousActivity.delete(key); // just in case
    }
  }

  /** Stats for monitoring */
  getStats() {
    return {
      activeBans: this.bans.size,
      trackedIPs: Array.from(this.requestCounts.keys()).filter(k => k.startsWith('ip:')).length,
      trackedUsers: Array.from(this.requestCounts.keys()).filter(k => k.startsWith('user:')).length,
    };
  }
}
