// app.js
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const app = express();
app.use(express.json());

// ===== Configurações simples =====
const users = {}; // { email: { passwordHash, resetToken } }
const sessions = {}; // { refreshToken: email }
const ACCESS_SECRET = "access-secret";
const REFRESH_SECRET = "refresh-secret";

// Gera par de chaves RSA para proteger AES
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });

// ===== Funções utilitárias =====
function log(event, details) {
  console.log(`[LOG] ${event}`, details);
}

function generateAccessToken(email) {
  return jwt.sign({ email }, ACCESS_SECRET, { expiresIn: "15m" });
}
function generateRefreshToken(email) {
  const token = jwt.sign({ email }, REFRESH_SECRET, { expiresIn: "7d" });
  sessions[token] = email;
  return token;
}

// ===== Registro =====
app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  const hash = await bcrypt.hash(password, 10); // bcrypt já usa salt
  users[email] = { passwordHash: hash };
  log("user_registered", { email });
  res.json({ message: "Usuário registrado" });
});

// ===== Login =====
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = users[email];
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({ error: "Credenciais inválidas" });
  }
  const accessToken = generateAccessToken(email);
  const refreshToken = generateRefreshToken(email);
  log("login_success", { email });
  res.json({ accessToken, refreshToken });
});

// ===== Refresh =====
app.post("/refresh", (req, res) => {
  const { refreshToken } = req.body;
  if (!sessions[refreshToken]) return res.status(401).json({ error: "Token inválido" });
  try {
    const payload = jwt.verify(refreshToken, REFRESH_SECRET);
    const newAccess = generateAccessToken(payload.email);
    const newRefresh = generateRefreshToken(payload.email);
    delete sessions[refreshToken]; // revoga antigo
    log("refresh_rotated", { email: payload.email });
    res.json({ accessToken: newAccess, refreshToken: newRefresh });
  } catch {
    res.status(401).json({ error: "Token inválido" });
  }
});

// ===== Logout =====
app.post("/logout", (req, res) => {
  const { refreshToken } = req.body;
  delete sessions[refreshToken];
  log("logout", { refreshToken });
  res.json({ message: "Sessão encerrada" });
});

// ===== Recuperação de senha =====
app.post("/request-reset", (req, res) => {
  const { email } = req.body;
  if (!users[email]) return res.json({ message: "Se existir, enviamos e-mail" });
  const token = crypto.randomBytes(16).toString("hex");
  users[email].resetToken = token;
  log("password_reset_requested", { email, token });
  res.json({ message: "Token gerado (simulado)", token });
});

app.post("/reset-password", async (req, res) => {
  const { email, token, newPassword } = req.body;
  if (!users[email] || users[email].resetToken !== token) return res.status(400).json({ error: "Token inválido" });
  users[email].passwordHash = await bcrypt.hash(newPassword, 10);
  delete users[email].resetToken;
  log("password_reset_success", { email });
  res.json({ message: "Senha redefinida" });
});

// ===== Alteração de senha autenticada =====
app.post("/change-password", async (req, res) => {
  const { email, currentPassword, newPassword } = req.body;
  const user = users[email];
  if (!user || !(await bcrypt.compare(currentPassword, user.passwordHash))) {
    return res.status(401).json({ error: "Senha atual inválida" });
  }
  user.passwordHash = await bcrypt.hash(newPassword, 10);
  log("password_changed", { email });
  res.json({ message: "Senha alterada" });
});

// ===== Criptografia de mensagens =====
app.post("/encrypt", (req, res) => {
  const { message } = req.body;
  const aesKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", aesKey, iv);
  let encrypted = cipher.update(message, "utf8", "hex");
  encrypted += cipher.final("hex");
  const aesKeyEncrypted = crypto.publicEncrypt(publicKey, aesKey);
  log("message_encrypted", { length: message.length });
  res.json({ encrypted, iv: iv.toString("hex"), aesKeyEncrypted: aesKeyEncrypted.toString("hex") });
});

app.post("/decrypt", (req, res) => {
  const { encrypted, iv, aesKeyEncrypted } = req.body;
  const aesKey = crypto.privateDecrypt(privateKey, Buffer.from(aesKeyEncrypted, "hex"));
  const decipher = crypto.createDecipheriv("aes-256-cbc", aesKey, Buffer.from(iv, "hex"));
  let decrypted = decipher.update(encrypted, "hex", "utf8");
  decrypted += decipher.final("utf8");
  log("message_decrypted", { length: decrypted.length });
  res.json({ message: decrypted });
});

// ===== Start =====
app.listen(3000, () => console.log("Servidor básico rodando na porta 3000"));
