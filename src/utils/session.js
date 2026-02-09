const { redisClient } = require('../config/redis.config');

/**
 * Invalidate all sessions for a specific user
 * Use this when user logs in to prevent old session IDs from being reused
 * 
 * @param {number} userId - The user ID whose sessions should be invalidated
 * @returns {Promise<number>} Number of sessions deleted
 */
async function invalidateAllUserSessions(userId) {
    try {
        const prefix = process.env.REDIS_SESSION_PREFIX || 'vulab:';
        const pattern = `${prefix}*`; // Match all session keys
        
        let deletedCount = 0;
        let cursor = 0;
        
        // Scan through all session keys in Redis
        do {
            const result = await redisClient.scan(cursor, {
                MATCH: pattern,
                COUNT: 100
            });
            
            cursor = result.cursor;
            const keys = result.keys;
            
            // Check each session to see if it belongs to this user
            for (const key of keys) {
                try {
                    const sessionData = await redisClient.get(key);
                    if (sessionData) {
                        const session = JSON.parse(sessionData);
                        // If this session belongs to the user, delete it
                        if (session.userId === userId) {
                            await redisClient.del(key);
                            deletedCount++;
                        }
                    }
                } catch (err) {
                    // Skip invalid session data
                    console.error(`Failed to parse session ${key}:`, err);
                }
            }
        } while (cursor !== 0);
        
        return deletedCount;
    } catch (error) {
        console.error('Failed to invalidate user sessions:', error);
        throw error;
    }
}

/**
 * Promisify req.session.regenerate()
 * @param {Object} session - Express session object
 * @returns {Promise<void>}
 */
function regenerateSession(session) {
    return new Promise((resolve, reject) => {
        session.regenerate((err) => {
            if (err) reject(err);
            else resolve();
        });
    });
}

/**
 * Promisify req.session.destroy()
 * @param {Object} session - Express session object
 * @returns {Promise<void>}
 */
function destroySession(session) {
    return new Promise((resolve, reject) => {
        session.destroy((err) => {
            if (err) reject(err);
            else resolve();
        });
    });
}

module.exports = {
    invalidateAllUserSessions,
    regenerateSession,
    destroySession
};
