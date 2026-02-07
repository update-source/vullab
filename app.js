const express = require('express');
const session = require('./src/config/session')
const { connectRedis } = require('./src/config/redis');
const app = express();
const port = 3000;
const useragent = require('express-useragent');

app.use(express.static('public'))
app.set('view engine', 'pug');
app.set('views', 'views');

app.use(useragent.express())
app.use(session);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes
const routes = require('./src/routes');
app.use('/api', routes); // Prefix cho tất cả API là /api

const { errorHandler } = require('./src/middlewares');

app.get('/', (req, res) => {
    res.render('index', {
        title: 'Trang Chủ',
        message: 'Xin chào, đây là Pug!'
    });
});

// Global Error Handler must be the last middleware
app.use(errorHandler);

// Start server with Redis connection
const startServer = async () => {
    try {
        await connectRedis();

        app.listen(port, () => {
            console.log(`Server đang chạy tại http://localhost:${port}`);
        });
    } catch (err) {
        console.error('❌ Failed to start server:', err.message);
    }
};


startServer();