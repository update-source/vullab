const express = require('express');
const app = express();
const port = 3000;
const { sequelize } = require('./src/config/database');

app.use(express.static('public'))
app.set('view engine', 'pug');
app.set('views', 'views');

// Middleware xử lý JSON body (bắt buộc để backend đọc được req.body)
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

// Database synchronization should be done via specific scripts (npm run db:sync), not on server start.
// (async () => {
//     await sequelize.sync({ force: true });
//     console.log('All models were synchronized successfully.');
// })();

// Global Error Handler must be the last middleware
app.use(errorHandler);

app.listen(port, () => {
    console.log(`Server đang chạy tại http://localhost:${port}`);
});