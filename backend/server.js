// backend/server.js
import express from "express";
import cors from "cors";
import sqlite3 from "sqlite3";
import { open } from "sqlite";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import multer from "multer";
import path from "path";
import { fileURLToPath } from "url";
import fs from "fs";

dotenv.config();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "troque_essa_chave_em_producao";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const uploadFolder = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadFolder)) fs.mkdirSync(uploadFolder, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadFolder),
  filename: (req, file, cb) => {
    const unique = Date.now() + "-" + Math.round(Math.random()*999999);
    cb(null, unique + "-" + file.originalname.replace(/\s+/g, "_"));
  }
});
const upload = multer({ storage });

const app = express();
app.use(cors());
app.use(express.json());
app.use("/uploads", express.static(uploadFolder));

let db;
async function initDb(){
  db = await open({ filename: "./database.sqlite", driver: sqlite3.Database });

  // Usuários
  await db.exec(`
    CREATE TABLE IF NOT EXISTS usuarios (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nome TEXT NOT NULL,
      cargo TEXT,
      departamento TEXT,
      email TEXT UNIQUE NOT NULL,
      senha TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'attendant',
      ativo INTEGER DEFAULT 1,
      criadoEm TEXT DEFAULT (datetime('now','localtime'))
    );
  `);

  // Atendimentos - inclui userId e outros campos solicitados
  await db.exec(`
    CREATE TABLE IF NOT EXISTS atendimentos (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      userId INTEGER, 
      clienteNome TEXT NOT NULL,
      clienteTelefone TEXT,
      clienteEmail TEXT,
      assunto TEXT NOT NULL,
      descricao TEXT,
      duracaoTotal TEXT,
      dataCriacao TEXT DEFAULT (datetime('now','localtime')),
      arquivo TEXT,
      status TEXT NOT NULL DEFAULT 'Em andamento',
      prioridade TEXT NOT NULL DEFAULT 'Normal',
      FOREIGN KEY(userId) REFERENCES usuarios(id)
    );
  `);

  // seed inicial se vazio
  const u = await db.get("SELECT COUNT(*) AS c FROM usuarios");
  if (u && u.c === 0){
    const hash = await bcrypt.hash("admin123", 10);
    await db.run("INSERT INTO usuarios (nome, cargo, departamento, email, senha, role) VALUES (?, ?, ?, ?, ?, ?)",
      ["Administrador", "Admin", "TI", "admin@fixa.com", hash, "admin"]);
    console.log("Usuário admin inicial criado: admin@fixa.com / admin123");
  }
}
await initDb();

/* ----------------- helpers & middleware ----------------- */

function signToken(user){
  return jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: "8h" });
}

async function getUserById(id){
  return await db.get("SELECT id, nome, cargo, departamento, email, role, ativo, criadoEm FROM usuarios WHERE id = ?", [id]);
}

async function authMiddleware(req, res, next){
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) return res.status(401).json({ erro: "Não autorizado" });
  const token = auth.split(" ")[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = await getUserById(payload.id);
    if (!req.user) return res.status(401).json({ erro: "Usuário inválido" });
    req.userId = payload.id;
    req.userRole = payload.role;
    next();
  } catch (err) {
    return res.status(401).json({ erro: "Token inválido" });
  }
}

function requireAdmin(req, res, next){
  if (!req.userRole || req.userRole !== "admin") return res.status(403).json({ erro: "Permissão negada" });
  next();
}

/* ----------------- auth & user routes ----------------- */

// rota pública setup: cria primeiro admin se não houver usuários
app.post("/setup", async (req, res) => {
  try {
    const row = await db.get("SELECT COUNT(*) AS c FROM usuarios");
    if (row && row.c > 0) return res.status(400).json({ erro: "Setup já executado" });
    const { nome, cargo, departamento, email, senha } = req.body;
    if (!nome || !email || !senha) return res.status(400).json({ erro: "Dados incompletos" });
    const hash = await bcrypt.hash(senha, 10);
    const r = await db.run("INSERT INTO usuarios (nome, cargo, departamento, email, senha, role) VALUES (?, ?, ?, ?, ?, ?)",
      [nome, cargo || "Admin", departamento || "", email, hash, "admin"]);
    const user = await getUserById(r.lastID);
    return res.json({ sucesso: true, user });
  } catch (err) {
    console.error(err); return res.status(500).json({ erro: "Erro no setup" });
  }
});

// login
app.post("/auth/login", async (req, res) => {
  try {
    const { email, senha } = req.body;
    if (!email || !senha) return res.status(400).json({ erro: "Dados incompletos" });
    const row = await db.get("SELECT * FROM usuarios WHERE email = ?", [email]);
    if (!row) return res.status(400).json({ erro: "Usuário não encontrado" });
    if (!row.ativo) return res.status(403).json({ erro: "Conta desativada" });
    const ok = await bcrypt.compare(senha, row.senha);
    if (!ok) return res.status(400).json({ erro: "Senha incorreta" });

    const token = signToken(row);
    const user = await getUserById(row.id);
    res.json({ token, user });
  } catch (err) {
    console.error(err); res.status(500).json({ erro: "Erro ao autenticar" });
  }
});

// criar usuário (admin)
app.post("/usuarios", authMiddleware, requireAdmin, async (req, res) => {
  try {
    const { nome, cargo, departamento, email, senha, role = "attendant" } = req.body;
    if (!nome || !email || !senha) return res.status(400).json({ erro: "Dados incompletos" });
    const hash = await bcrypt.hash(senha, 10);
    const r = await db.run("INSERT INTO usuarios (nome, cargo, departamento, email, senha, role) VALUES (?, ?, ?, ?, ?, ?)",
      [nome, cargo || "", departamento || "", email, hash, role]);
    const user = await getUserById(r.lastID);
    res.status(201).json(user);
  } catch (err) {
    console.error(err);
    if (err && err.code === "SQLITE_CONSTRAINT") return res.status(400).json({ erro: "E-mail já cadastrado" });
    res.status(500).json({ erro: "Erro ao criar usuário" });
  }
});

// listar usuarios (admin)
app.get("/usuarios", authMiddleware, requireAdmin, async (req,res) => {
  try {
    const rows = await db.all("SELECT id, nome, cargo, departamento, email, role, ativo, criadoEm FROM usuarios ORDER BY criadoEm DESC");
    res.json(rows);
  } catch (err) { console.error(err); res.status(500).json({ erro: "Erro" }); }
});

// editar / ativar / desativar (admin)
app.patch("/usuarios/:id", authMiddleware, requireAdmin, async (req,res) => {
  try {
    const id = Number(req.params.id);
    const { nome, cargo, departamento, role, ativo } = req.body;
    const existing = await db.get("SELECT * FROM usuarios WHERE id = ?", [id]);
    if (!existing) return res.status(404).json({ erro: "Usuário não encontrado" });
    const newNome = nome ?? existing.nome;
    const newCargo = cargo ?? existing.cargo;
    const newDept = departamento ?? existing.departamento;
    const newRole = role ?? existing.role;
    const newAtivo = (typeof ativo === "number") ? ativo : existing.ativo;
    await db.run("UPDATE usuarios SET nome=?, cargo=?, departamento=?, role=?, ativo=? WHERE id = ?", [newNome, newCargo, newDept, newRole, newAtivo, id]);
    const u = await getUserById(id);
    res.json(u);
  } catch (err) { console.error(err); res.status(500).json({ erro: "Erro ao atualizar usuário" }); }
});

// rota para retornar meu perfil
app.get("/me", authMiddleware, async (req,res) => {
  res.json(req.user);
});

/* ----------------- atendimentos (ligados a userId) ----------------- */

// listar atendimentos
app.get("/atendimentos", authMiddleware, async (req,res) => {
  try {
    // admins veem tudo; atendentes veem somente os seus
    if (req.userRole === "admin") {
      const rows = await db.all("SELECT * FROM atendimentos ORDER BY dataCriacao DESC");
      const list = rows.map(r => ({ ...r, dataCriacao: r.dataCriacao ? new Date(r.dataCriacao + "Z").toLocaleString("pt-BR",{dateStyle:"short", timeStyle:"short"}) : "" }));
      return res.json(list);
    } else {
      const rows = await db.all("SELECT * FROM atendimentos WHERE userId = ? ORDER BY dataCriacao DESC", [req.userId]);
      const list = rows.map(r => ({ ...r, dataCriacao: r.dataCriacao ? new Date(r.dataCriacao + "Z").toLocaleString("pt-BR",{dateStyle:"short", timeStyle:"short"}) : "" }));
      return res.json(list);
    }
  } catch (err) { console.error(err); res.status(500).json({ erro: "Erro ao listar atendimentos" }); }
});

// obter 1 atendimento
app.get("/atendimentos/:id", authMiddleware, async (req,res) => {
  try {
    const id = Number(req.params.id);
    const r = await db.get("SELECT * FROM atendimentos WHERE id = ?", [id]);
    if (!r) return res.status(404).json({ erro: "Atendimento não encontrado" });
    // autorização: admin ou proprietário
    if (req.userRole !== "admin" && r.userId !== req.userId) return res.status(403).json({ erro: "Acesso negado" });
    r.dataCriacao = r.dataCriacao ? new Date(r.dataCriacao + "Z").toLocaleString("pt-BR",{dateStyle:"short",timeStyle:"short"}) : "";
    res.json(r);
  } catch (err) { console.error(err); res.status(500).json({ erro: "Erro" }); }
});

// criar atendimento (upload opcional). se admin pode definir userId no body; senão userId = req.userId
app.post("/atendimentos", authMiddleware, upload.single("arquivo"), async (req,res) => {
  try {
    const {
      clienteNome, clienteTelefone, clienteEmail, assunto, descricao, duracaoTotal, status = "Em andamento", prioridade = "Normal", userId: bodyUserId
    } = req.body;

    if (!clienteNome || !assunto || !duracaoTotal) return res.status(400).json({ erro: "Campos obrigatórios: clienteNome, assunto, duracaoTotal" });

    let ownerId = req.userId;
    if (req.userRole === "admin" && bodyUserId) ownerId = Number(bodyUserId);

    let caminho = null;
    if (req.file) caminho = "/uploads/" + req.file.filename;

    const r = await db.run("INSERT INTO atendimentos (userId, clienteNome, clienteTelefone, clienteEmail, assunto, descricao, duracaoTotal, dataCriacao, arquivo, status, prioridade) VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now','localtime'), ?, ?, ?)",
      [ownerId, clienteNome, clienteTelefone, clienteEmail, assunto, descricao, duracaoTotal, caminho, status, prioridade]);

    const novo = await db.get("SELECT * FROM atendimentos WHERE id = ?", [r.lastID]);
    novo.dataCriacao = novo.dataCriacao ? new Date(novo.dataCriacao + "Z").toLocaleString("pt-BR",{dateStyle:"short",timeStyle:"short"}) : "";
    res.status(201).json(novo);
  } catch (err) { console.error(err); res.status(500).json({ erro: "Erro ao criar atendimento" }); }
});

// atualizar (apenas admin ou dono)
app.patch("/atendimentos/:id", authMiddleware, async (req,res) => {
  try {
    const id = Number(req.params.id);
    const existing = await db.get("SELECT * FROM atendimentos WHERE id = ?", [id]);
    if (!existing) return res.status(404).json({ erro: "Atendimento não encontrado" });
    if (req.userRole !== "admin" && existing.userId !== req.userId) return res.status(403).json({ erro: "Acesso negado" });

    const { status, duracaoTotal, descricao, prioridade } = req.body;
    const newStatus = status ?? existing.status;
    const newDur = duracaoTotal ?? existing.duracaoTotal;
    const newDesc = descricao ?? existing.descricao;
    const newPrio = prioridade ?? existing.prioridade;

    await db.run("UPDATE atendimentos SET status = ?, duracaoTotal = ?, descricao = ?, prioridade = ? WHERE id = ?", [newStatus, newDur, newDesc, newPrio, id]);
    const updated = await db.get("SELECT * FROM atendimentos WHERE id = ?", [id]);
    updated.dataCriacao = updated.dataCriacao ? new Date(updated.dataCriacao + "Z").toLocaleString("pt-BR",{dateStyle:"short",timeStyle:"short"}) : "";
    res.json(updated);
  } catch (err) { console.error(err); res.status(500).json({ erro: "Erro ao atualizar" }); }
});

// dashboard: se admin retorna geral, se attendant filtra por userId
app.get("/dashboard", authMiddleware, async (req,res) => {
  try {
    if (req.userRole === "admin"){
      const total = (await db.get("SELECT COUNT(*) AS c FROM atendimentos")).c || 0;
      const andamento = (await db.get("SELECT COUNT(*) AS c FROM atendimentos WHERE status = 'Em andamento'")).c || 0;
      const concluidos = (await db.get("SELECT COUNT(*) AS c FROM atendimentos WHERE status LIKE 'Conclu%'")).c || 0;
      const urgentes = (await db.get("SELECT COUNT(*) AS c FROM atendimentos WHERE prioridade IN ('Urgente','Alta')")).c || 0;
      const meses = []; const valores = []; const now = new Date();
      for (let i=5;i>=0;i--){
        const d=new Date(now.getFullYear(), now.getMonth()-i,1);
        meses.push(d.toLocaleString("pt-BR",{month:"short",year:"numeric"}));
        const start = new Date(d.getFullYear(),d.getMonth(),1).toISOString();
        const end = new Date(d.getFullYear(),d.getMonth()+1,1).toISOString();
        const row = await db.get("SELECT COUNT(*) AS c FROM atendimentos WHERE dataCriacao >= ? AND dataCriacao < ?", [start,end]);
        valores.push(row.c || 0);
      }
      return res.json({ total, andamento, concluidos, urgentes, grafico:{ meses, valores }});
    } else {
      // apenas do user
      const total = (await db.get("SELECT COUNT(*) AS c FROM atendimentos WHERE userId = ?", [req.userId])).c || 0;
      const andamento = (await db.get("SELECT COUNT(*) AS c FROM atendimentos WHERE userId = ? AND status = 'Em andamento'", [req.userId])).c || 0;
      const concluidos = (await db.get("SELECT COUNT(*) AS c FROM atendimentos WHERE userId = ? AND status LIKE 'Conclu%'", [req.userId])).c || 0;
      const urgentes = (await db.get("SELECT COUNT(*) AS c FROM atendimentos WHERE userId = ? AND prioridade IN ('Urgente','Alta')", [req.userId])).c || 0;
      const meses=[]; const valores=[]; const now=new Date();
      for (let i=5;i>=0;i--){
        const d=new Date(now.getFullYear(), now.getMonth()-i,1);
        meses.push(d.toLocaleString("pt-BR",{month:"short",year:"numeric"}));
        const start = new Date(d.getFullYear(),d.getMonth(),1).toISOString();
        const end = new Date(d.getFullYear(),d.getMonth()+1,1).toISOString();
        const row = await db.get("SELECT COUNT(*) AS c FROM atendimentos WHERE userId = ? AND dataCriacao >= ? AND dataCriacao < ?", [req.userId, start, end]);
        valores.push(row.c || 0);
      }
      return res.json({ total, andamento, concluidos, urgentes, grafico:{ meses, valores }});
    }
  } catch (err) { console.error(err); res.status(500).json({ erro: "Erro ao montar dashboard" }); }
});

// relatorios/meses (12 meses) - similar ao dashboard, admin ou user
app.get("/relatorios/meses", authMiddleware, async (req,res) => {
  try {
    const meses=[]; const valores=[]; const now=new Date();
    for (let i=11;i>=0;i--){
      const d=new Date(now.getFullYear(), now.getMonth()-i,1);
      meses.push(d.toLocaleString("pt-BR",{month:"short", year:"numeric"}));
      const start = new Date(d.getFullYear(),d.getMonth(),1).toISOString();
      const end = new Date(d.getFullYear(),d.getMonth()+1,1).toISOString();
      let row;
      if (req.userRole === "admin") row = await db.get("SELECT COUNT(*) AS c FROM atendimentos WHERE dataCriacao >= ? AND dataCriacao < ?", [start,end]);
      else row = await db.get("SELECT COUNT(*) AS c FROM atendimentos WHERE userId = ? AND dataCriacao >= ? AND dataCriacao < ?", [req.userId, start,end]);
      valores.push(row.c || 0);
    }
    res.json({ meses, valores });
  } catch (err) { console.error(err); res.status(500).json({ erro: "Erro ao gerar relatório" }); }
});

/* start server */
app.listen(PORT, () => console.log(`API rodando em http://localhost:${PORT}`));
