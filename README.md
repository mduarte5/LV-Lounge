LV Lounge — API básica de segurança e LGPD
Stack: Node.js + Express

Recursos: registro/login, access/refresh JWT, reset e troca de senha, criptografia AES com proteção RSA, controle de sessões, logs.

Instalação
Passos:

Instalar dependências: npm install express bcrypt jsonwebtoken

Gerar chaves RSA: ver instrução acima.

Rodar: node src/app.js

Endpoints
POST /register: email, password

POST /login: email, password → accessToken, refreshToken

POST /refresh: refreshToken → novo par

POST /logout: refreshToken → encerra sessão

POST /request-reset: email → token temporário (demo)

POST /reset-password: email, token, newPassword

POST /change-password: Bearer accessToken, currentPassword, newPassword

POST /encrypt: Bearer accessToken, message → id

POST /decrypt: Bearer accessToken, id → message

Observações
Memória: sem banco (didático). Em produção, troque stores por um banco com expiração.

Segredos: use .env e um vault em produção.

LGPD: limitar coleta, registrar consentimentos e oferecer direitos dos titulares.
