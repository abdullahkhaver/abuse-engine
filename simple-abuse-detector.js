// File: simple-abuse-detector.js
class SimpleAbuseDetector {
    constructor() {
        // Store request counts per identifier
        this.requestCounts = new Map();
        // Store banned identifiers
        this.bans = new Map();
        // Track suspicious activities
        this.suspiciousActivity = new Map();
        
        // Configuration
        this.config = {
            // Rate limits (requests per window)
            ipLimit: 100,        // 100 requests per minute per IP
            userLimit: 50,       // 50 requests per minute per user
            windowMs: 60 * 1000, // 1 minute window
            
            // Abuse thresholds
            maxAuthFailures: 5,  // 5 failed auth attempts
            banDuration: 15 * 60 * 1000, // 15 minute ban
            suspiciousPaths: ['/admin', '/api/auth', '/api/users']
        };
    }

    // Extract identity from request
    extractIdentity(req) {
        return {
            ip: req.ip || req.connection.remoteAddress,
            userId: req.headers['x-user-id'] || req.session?.userId || 'anonymous',
            apiKey: req.headers['api-key'],
            path: req.path,
            method: req.method
        };
    }

    // Check if identifier is banned
    isBanned(identifier) {
        const ban = this.bans.get(identifier);
        if (!ban) return false;
        
        if (Date.now() > ban.expiresAt) {
            this.bans.delete(identifier); // Ban expired
            return false;
        }
        
        return true;
    }

    // Check rate limit
    checkRateLimit(identity) {
        const now = Date.now();
        const windowStart = now - this.config.windowMs;
        
        // Check IP limit
        const ipKey = `ip:${identity.ip}`;
        if (!this.requestCounts.has(ipKey)) {
            this.requestCounts.set(ipKey, []);
        }
        
        // Remove old entries outside the window
        const ipRequests = this.requestCounts.get(ipKey);
        while (ipRequests.length > 0 && ipRequests[0] < windowStart) {
            ipRequests.shift();
        }
        
        // Check if over limit
        if (ipRequests.length >= this.config.ipLimit) {
            return { allowed: false, reason: 'IP rate limit exceeded' };
        }
        
        // Add current request
        ipRequests.push(now);
        
        // Check user limit if user is authenticated
        if (identity.userId !== 'anonymous') {
            const userKey = `user:${identity.userId}`;
            if (!this.requestCounts.has(userKey)) {
                this.requestCounts.set(userKey, []);
            }
            
            const userRequests = this.requestCounts.get(userKey);
            while (userRequests.length > 0 && userRequests[0] < windowStart) {
                userRequests.shift();
            }
            
            if (userRequests.length >= this.config.userLimit) {
                return { allowed: false, reason: 'User rate limit exceeded' };
            }
            
            userRequests.push(now);
        }
        
        return { allowed: true };
    }

    // Detect suspicious behavior
    detectSuspiciousBehavior(identity, req) {
        const signals = [];
        
        // Check for auth failures
        if (req.path.includes('/login') || req.path.includes('/auth')) {
            if (req.statusCode === 401 || req.statusCode === 403) {
                const key = `auth_fail:${identity.ip}`;
                const count = (this.suspiciousActivity.get(key) || 0) + 1;
                this.suspiciousActivity.set(key, count);
                
                if (count >= this.config.maxAuthFailures) {
                    signals.push('Multiple auth failures');
                    this.banIdentifier(identity.ip, 'Excessive auth failures');
                }
            }
        }
        
        // Check suspicious paths
        if (this.config.suspiciousPaths.some(path => req.path.includes(path))) {
            const key = `suspicious_path:${identity.ip}`;
            const count = (this.suspiciousActivity.get(key) || 0) + 1;
            this.suspiciousActivity.set(key, count);
            
            if (count > 3) {
                signals.push('Scanning sensitive paths');
            }
        }
        
        return signals;
    }

    // Ban an identifier
    banIdentifier(identifier, reason) {
        this.bans.set(identifier, {
            reason,
            bannedAt: Date.now(),
            expiresAt: Date.now() + this.config.banDuration
        });
        console.log(`[SECURITY] Banned ${identifier}: ${reason}`);
    }

    // Main middleware function
    middleware() {
        return (req, res, next) => {
            // Extract identity
            const identity = this.extractIdentity(req);
            
            // Check bans
            if (this.isBanned(identity.ip)) {
                return res.status(403).json({
                    error: 'Access temporarily blocked',
                    message: 'Too many suspicious activities'
                });
            }
            
            // Check rate limits
            const rateLimitResult = this.checkRateLimit(identity);
            if (!rateLimitResult.allowed) {
                return res.status(429).json({
                    error: 'Rate limit exceeded',
                    message: 'Too many requests'
                });
            }
            
            // Add response listener to detect suspicious behavior
            const originalSend = res.send;
            res.send = function(body) {
                // Store status for later analysis
                res.__abuseStatus = res.statusCode;
                return originalSend.call(this, body);
            };
            
            // After response is sent, analyze behavior
            res.on('finish', () => {
                const suspiciousSignals = this.detectSuspiciousBehavior(identity, {
                    ...req,
                    statusCode: res.statusCode
                });
                
                if (suspiciousSignals.length > 0) {
                    // Log suspicious activity
                    this.logSecurityEvent({
                        timestamp: new Date().toISOString(),
                        ip: identity.ip,
                        userId: identity.userId,
                        path: req.path,
                        method: req.method,
                        statusCode: res.statusCode,
                        signals: suspiciousSignals
                    });
                }
            });
            
            next();
        };
    }

    // Simple logging
    logSecurityEvent(event) {
        console.log('[SECURITY EVENT]', JSON.stringify(event, null, 2));
    }

    // Get stats (useful for monitoring)
    getStats() {
        return {
            activeBans: this.bans.size,
            trackedIPs: Array.from(this.requestCounts.keys())
                .filter(k => k.startsWith('ip:')).length,
            trackedUsers: Array.from(this.requestCounts.keys())
                .filter(k => k.startsWith('user:')).length
        };
    }

    // Cleanup old data (call periodically)
    cleanup() {
        const now = Date.now();
        
        // Remove old bans
        for (const [identifier, ban] of this.bans.entries()) {
            if (now > ban.expiresAt) {
                this.bans.delete(identifier);
            }
        }
        
        // Remove old request counts (older than 2 windows)
        const cutoff = now - (2 * this.config.windowMs);
        for (const [key, requests] of this.requestCounts.entries()) {
            const filtered = requests.filter(time => time > cutoff);
            if (filtered.length === 0) {
                this.requestCounts.delete(key);
            } else {
                this.requestCounts.set(key, filtered);
            }
        }
        
        // Clean suspicious activity (keep for 1 hour)
        const activityCutoff = now - (60 * 60 * 1000);
        for (const [key, timestamp] of this.suspiciousActivity.entries()) {
            if (timestamp < activityCutoff) {
                this.suspiciousActivity.delete(key);
            }
        }
    }
}

module.exports = SimpleAbuseDetector;