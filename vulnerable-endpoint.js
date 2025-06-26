const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// VULNERABILIDADE: Path Traversal
router.get('/download', (req, res) => {
    // Vulnerabilidade de path traversal - permite acessar arquivos fora do diretório pretendido
    const fileName = req.query.file;
    const filePath = path.join(__dirname, 'files', fileName);
    
    // Não há validação do caminho, permitindo path traversal com "../"
    fs.readFile(filePath, (err, data) => {
        if (err) {
            return res.status(404).send('File not found');
        }
        res.setHeader('Content-disposition', 'attachment; filename=' + fileName);
        res.send(data);
    });
});

// VULNERABILIDADE: Uso de algoritmo de criptografia fraco
router.post('/encrypt', (req, res) => {
    const { text } = req.body;
    
    // Uso de algoritmo de criptografia fraco (MD5)
    const hash = crypto.createHash('md5').update(text).digest('hex');
    
    res.json({ encrypted: hash });
});

// VULNERABILIDADE: Regex DoS (ReDoS)
router.post('/validate', (req, res) => {
    const { input } = req.body;
    
    // Regex vulnerável a ReDoS (Regex Denial of Service)
    const dangerousRegex = /^(([a-z])+.)+[A-Z]([a-z])+$/;
    
    const isValid = dangerousRegex.test(input);
    
    res.json({ valid: isValid });
});

// VULNERABILIDADE: Cross-Site Scripting (XSS)
router.get('/profile', (req, res) => {
    const username = req.query.username;
    
    // Saída não sanitizada, permitindo XSS
    res.send(`
        <html>
            <body>
                <h1>Perfil de ${username}</h1>
                <p>Bem-vindo ao seu perfil!</p>
            </body>
        </html>
    `);
});

// VULNERABILIDADE: Uso inseguro de eval()
router.post('/calculate', (req, res) => {
    const { expression } = req.body;
    
    try {
        // Uso extremamente perigoso de eval com entrada do usuário
        const result = eval(expression);
        res.json({ result });
    } catch (error) {
        res.status(400).json({ error: 'Invalid expression' });
    }
});

module.exports = router;