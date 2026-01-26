const express = require('express');
const app = express();
const port = 3000;

app.use(express.static('public'))
app.set('view engine', 'pug');
app.set('views', 'views');

app.get('/', (req, res) => {
    res.render('index', { 
        title: 'Trang Chủ', 
        message: 'Xin chào, đây là Pug!' 
    });
});

app.listen(port, () => {
    console.log(`Server đang chạy tại http://localhost:${port}`);
});