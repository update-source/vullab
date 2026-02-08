require('dotenv').config({ path: require('path').resolve(__dirname, '../../.env') });
const { createClient } = require('redis');
const RedisStore = require('connect-redis').default;

const redisClient = createClient({
    socket: {
        host: process.env.REDIS_HOST || 'localhost',
        port: parseInt(process.env.REDIS_PORT) || 6379,
        reconnectStrategy: (retries) => {
            if (retries > 10) {
                return new Error('Too many retries');
            }
            const delay = Math.min(retries * 50, 2000);
            console.log(`Reconnecting in ${delay}ms (attempt ${retries})`);
            return delay;
        },
    },
    password: process.env.REDIS_PASSWORD || undefined,
});

redisClient.on('error', (err) => {
    console.error('❌ Redis client error:', err);
});

const connectRedis = async () => {
    try {
        if (!redisClient.isOpen) {
            await redisClient.connect();
        }
    } catch (err) {
        console.error('❌ Failed to connect to Redis:', err);
        throw err;
    }
};

const redisStore = new RedisStore({
    client: redisClient,
    prefix: process.env.REDIS_SESSION_PREFIX || 'vulab:',
    ttl: 86400, // 24 hours in seconds
});

module.exports = {
    redisClient,
    redisStore,
    connectRedis,
};
