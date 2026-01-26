const fs = require('fs');
const path = require('path');

// Đọc file input CSS
const inputCSS = fs.readFileSync(path.join(__dirname, 'public/css/style.css'), 'utf8');

// Import Tailwind CSS
const tailwindCSS = fs.readFileSync(path.join(__dirname, 'node_modules/tailwindcss/index.css'), 'utf8');

// Tạo output CSS
const outputCSS = tailwindCSS + '\n\n' + inputCSS.replace(/@tailwind base;|@tailwind components;|@tailwind utilities;/g, '');

// Ghi vào file output
fs.writeFileSync(path.join(__dirname, 'public/css/output.css'), outputCSS);

console.log('✅ Tailwind CSS đã được build thành công!');
