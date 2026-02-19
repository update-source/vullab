const express = require('express');
const session = require('./src/config/session.config');
const { connectRedis } = require('./src/config/redis.config');
const cookieParser = require('cookie-parser');
const app = express();
const port = 3000;
const useragent = require('express-useragent');
const swaggerUi = require('swagger-ui-express');
const swaggerSpecs = require('./src/config/swagger.config');

app.use(express.static('public'))
app.set('view engine', 'pug');
app.set('views', 'views');

app.use(cookieParser());
app.use(useragent.express())
app.use(session);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Swagger UI
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpecs, {
    customCss: '.swagger-ui .topbar { display: none }',
    customSiteTitle: 'VulLab API Docs'
}));

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

// Start server
const startServer = async () => {
    try {
        // Redis connects automatically when redis.config.js is loaded
        app.listen(port, () => {
            console.log(`🚀 Server running at http://localhost:${port}`);
            console.log(`📚 API Docs available at http://localhost:${port}/api-docs`);
        });
    } catch (err) {
        console.error('❌ Failed to start server:', err.message);
        process.exit(1);
    }
};

startServer();