require('dotenv').config();
const crypto = require('crypto');
const fs     = require('fs');
const express = require('express');
const helmet  = require('helmet');
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const pdf = require('pdf-parse');
const OpenAI = require('openai');
const path = require('path');
const { createCanvas } = require('canvas');
const pdfjsLib = require('pdfjs-dist/legacy/build/pdf.js');
const { PDFDocument } = require('pdf-lib');
const archiver = require('archiver');

const DATA_DIR    = path.join(__dirname, 'data');
const HISTORY_FILE = path.join(DATA_DIR, 'history.json');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);

function saveToHistory(entry) {
  try {
    let history = fs.existsSync(HISTORY_FILE)
      ? JSON.parse(fs.readFileSync(HISTORY_FILE, 'utf8'))
      : [];
    history.push(entry);
    if (history.length > 20) history = history.slice(-20);
    fs.writeFileSync(HISTORY_FILE, JSON.stringify(history, null, 2));
  } catch (e) {
    console.error('Erro ao salvar histórico:', e.message);
  }
}

const app = express();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 1 * 1024 * 1024 }, // 1 MB
  fileFilter: (_req, file, cb) => {
    if (file.mimetype === 'application/pdf') cb(null, true);
    else cb(new Error('Apenas arquivos PDF são aceitos'));
  }
});

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// até 2 uploads por IP a cada 10 segundos (para suportar análise de 2 PDFs simultâneos)
const analyzeLimiter = rateLimit({
  windowMs: 10 * 1000,
  max: 2,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Aguarde 10 segundos antes de enviar outro arquivo.' }
});

// Proteção brute-force na autenticação: 5 tentativas por 15 minutos por IP
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Muitas tentativas. Aguarde 15 minutos.' }
});

// Gera nonce único por request — usado no CSP para blocos <script> inline
app.use((_req, res, next) => { res.locals.nonce = crypto.randomBytes(16).toString('base64'); next(); });

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:     ["'self'", 'https://cdn.jsdelivr.net', (_req, res) => `'nonce-${res.locals.nonce}'`],
      scriptSrcAttr: ["'unsafe-inline'"], // necessário para onclick/ondrop/ondragover no HTML
      styleSrc:      ["'self'", "'unsafe-inline'"],
      imgSrc:        ["'self'", 'data:'],
      connectSrc:    ["'self'"],
      fontSrc:       ["'self'"],
      objectSrc:     ["'none'"],
      frameAncestors: ["'none'"]
    }
  }
}));

// Impede indexação por crawlers
app.use((_req, res, next) => { res.setHeader('X-Robots-Tag', 'noindex, nofollow'); next(); });

app.use(express.json({ limit: '50kb' }));

// Cache-Control: no-store em todas as respostas de API (dados fiscais não devem ser cacheados)
app.use('/api', (_req, res, next) => { res.setHeader('Cache-Control', 'no-store'); next(); });

// Serve index.html dinamicamente para injetar o nonce no bloco <script>
app.get('/', (_req, res) => {
  const htmlPath = path.join(__dirname, 'public', 'index.html');
  let html = fs.readFileSync(htmlPath, 'utf8');
  html = html.replace('<script>', `<script nonce="${res.locals.nonce}">`);
  res.setHeader('Content-Type', 'text/html');
  res.send(html);
});

app.use(express.static(path.join(__dirname, 'public')));
app.use((req, _res, next) => { req.reqId = crypto.randomBytes(4).toString('hex'); next(); });

app.post('/api/history', (req, res) => {
  const { password } = req.body;
  if (!password || password !== process.env.ACCESS_PASSWORD) {
    return res.status(401).json({ error: 'Senha incorreta' });
  }
  try {
    let history = fs.existsSync(HISTORY_FILE)
      ? JSON.parse(fs.readFileSync(HISTORY_FILE, 'utf8'))
      : [];
    // Migra entradas sem id (geradas antes da versão com histórico)
    let migrated = false;
    history = history.map(e => {
      if (!e.id) { e.id = crypto.randomBytes(6).toString('hex'); migrated = true; }
      return e;
    });
    if (migrated) fs.writeFileSync(HISTORY_FILE, JSON.stringify(history, null, 2));
    res.json(history);
  } catch {
    res.json([]);
  }
});

app.post('/api/history/clear', (req, res) => {
  const { password } = req.body;
  if (!password || password !== process.env.ACCESS_PASSWORD) {
    return res.status(401).json({ error: 'Senha incorreta' });
  }
  try {
    fs.writeFileSync(HISTORY_FILE, '[]');
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/history/delete', (req, res) => {
  const { password, id } = req.body;
  if (!password || password !== process.env.ACCESS_PASSWORD) {
    return res.status(401).json({ error: 'Senha incorreta' });
  }
  if (!id || typeof id !== 'string' || !/^[0-9a-f]{12}$/.test(id)) {
    return res.status(400).json({ error: 'ID inválido.' });
  }
  try {
    if (!fs.existsSync(HISTORY_FILE)) return res.json({ ok: true });
    let history = JSON.parse(fs.readFileSync(HISTORY_FILE, 'utf8'));
    history = history.filter(e => e.id !== id);
    fs.writeFileSync(HISTORY_FILE, JSON.stringify(history, null, 2));
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/auth', authLimiter, (req, res) => {
  const { password } = req.body;
  if (password && password === process.env.ACCESS_PASSWORD) {
    return res.json({ ok: true });
  }
  res.status(401).json({ error: 'Senha incorreta' });
});

// Converte número brasileiro "1.234,56" → float 1234.56
function brToFloat(s) {
  return parseFloat(String(s).replace(/\./g, '').replace(',', '.')) || 0;
}

// Extrai até `max` números brasileiros (1.234,56 ou 0,00) de uma string
function extractBrNums(text, max = Infinity) {
  const re = /\d{1,3}(?:\.\d{3})*,\d{2}/g;
  const nums = [];
  let m;
  while ((m = re.exec(text)) !== null && nums.length < max) nums.push(brToFloat(m[0]));
  return nums;
}

// Extrai dados numéricos diretamente do texto bruto do PDF.
// Estratégia: o pdf-parse cola datas+valores sem espaço ("01/20255.091,75"),
// então usamos regex que reconhece números no formato brasileiro diretamente,
// sem precisar normalizar o texto primeiro.
function extractNumericalData(text) {
  const out = {};

  // --- Faturamento mensal ---
  // Captura MM/AAAA + número BR imediatamente a seguir (com ou sem espaço)
  const dateValRe = /(\d{2}\/\d{4})\s*(\d{1,3}(?:\.\d{3})*,\d{2})/g;
  let int_ = {}, ext_ = {};

  // Usa padrão com ")" para evitar falso positivo em "Versão 2.2.27" no cabeçalho
  const idx221 = text.search(/2\.2\.1\)/i);
  const idx222 = text.search(/2\.2\.2\)/i);
  if (idx221 >= 0 && idx222 >= 0 && idx221 < idx222) {
    const endSec = (() => { const i = text.search(/2\.3[\s.)]|Folha de Sal/); return i > idx222 ? i : text.length; })();
    let m;
    dateValRe.lastIndex = 0;
    while ((m = dateValRe.exec(text.slice(idx221, idx222))) !== null) { if (!int_[m[1]]) int_[m[1]] = brToFloat(m[2]); }
    dateValRe.lastIndex = 0;
    while ((m = dateValRe.exec(text.slice(idx222, endSec))) !== null) { if (!ext_[m[1]]) ext_[m[1]] = brToFloat(m[2]); }
    console.log(`[REGEX] 2.2.1/2.2.2: interno=${Object.keys(int_).length} meses, externo=${Object.keys(ext_).length} meses`);
  }

  if (Object.keys(int_).length < 3) {
    console.log('[REGEX] Fallback: varrendo documento inteiro');
    int_ = {}; ext_ = {};
    let m;
    dateValRe.lastIndex = 0;
    while ((m = dateValRe.exec(text)) !== null) { if (!int_[m[1]]) int_[m[1]] = brToFloat(m[2]); }
    console.log(`[REGEX] Fallback: ${Object.keys(int_).length} meses`);
  }

  const months = [...new Set([...Object.keys(int_), ...Object.keys(ext_)])].sort((a, b) => {
    const [ma, ya] = a.split('/').map(Number), [mb, yb] = b.split('/').map(Number);
    return ya !== yb ? ya - yb : ma - mb;
  });
  if (months.length >= 3) {
    out.faturamento_mensal = months.map(mes => ({ mes, interno: int_[mes] ?? 0, externo: ext_[mes] ?? 0 }));
  }

  // --- Resumo: RPA, RBT12, RBA, RBAA ---
  // Após cada label extrai os 2 primeiros números BR (interno + externo)
  const resumo = {};
  for (const [key, label] of [['rpa','RPA'],['rbt12','RBT12'],['rba','RBA'],['rbaa','RBAA']]) {
    const labelIdx = text.search(new RegExp(`\\b${label}\\b`, 'i'));
    if (labelIdx >= 0) {
      const nums = extractBrNums(text.slice(labelIdx, labelIdx + 300), 2);
      if (nums.length >= 1) {
        resumo[`${key}_interno`] = nums[0];
        resumo[`${key}_externo`] = nums[1] ?? 0;
      }
    }
  }
  if (Object.keys(resumo).length === 8) out.resumo = resumo;

  // --- Tributos: último "Total do Débito Exigível" (9 valores consecutivos) ---
  let lastTribIdx = -1;
  const tRe = /Total do D[eé]bito Exig[ií]vel/gi;
  let tm;
  while ((tm = tRe.exec(text)) !== null) lastTribIdx = tm.index;
  if (lastTribIdx >= 0) {
    const nums = extractBrNums(text.slice(lastTribIdx, lastTribIdx + 600), 9);
    if (nums.length === 9) {
      out.tributos = {
        irpj: nums[0], csll: nums[1], cofins: nums[2], pis: nums[3],
        inss_cpp: nums[4], icms: nums[5], ipi: nums[6], iss: nums[7], total: nums[8]
      };
    }
    console.log(`[REGEX] tributos: ${nums.length}/9 valores`);
  }

  return out;
}

const PDFJS_FONTS_URL = path.join(__dirname, 'node_modules/pdfjs-dist/standard_fonts/');

// Converte páginas do PDF em imagens base64 JPEG usando pdfjs-dist + canvas
async function pdfToImages(pdfBuffer) {
  const loadingTask = pdfjsLib.getDocument({
    data: new Uint8Array(pdfBuffer),
    standardFontDataUrl: PDFJS_FONTS_URL
  });
  const pdfDoc = await loadingTask.promise;
  const images = [];
  for (let i = 1; i <= Math.min(pdfDoc.numPages, 4); i++) {
    const page = await pdfDoc.getPage(i);
    const viewport = page.getViewport({ scale: 2.0 });
    const canvas = createCanvas(viewport.width, viewport.height);
    const ctx = canvas.getContext('2d');
    await page.render({ canvasContext: ctx, viewport }).promise;
    images.push(canvas.toDataURL('image/jpeg', 0.85).split(',')[1]);
  }
  return images;
}

// Extrai dados do PDF via GPT-4o Vision (fallback quando total_das <= 1000)
async function extractWithVision(pdfBuffer) {
  console.log('[VISION] Iniciando extração por visão com gpt-4o');
  const images = await pdfToImages(pdfBuffer);
  const imageContent = images.map(img => ({
    type: 'image_url',
    image_url: { url: `data:image/jpeg;base64,${img}`, detail: 'high' }
  }));

  const completion = await openai.chat.completions.create({
    model: 'gpt-4o',
    messages: [{
      role: 'user',
      content: [
        {
          type: 'text',
          text: `Você é um especialista em extrair dados de extratos do Simples Nacional (PGDAS-D) do Brasil.
Analise as imagens do documento e retorne SOMENTE um JSON válido, sem markdown, sem texto extra.

Estrutura esperada:
{
  "empresa": "nome empresarial completo",
  "cnpj": "XX.XXX.XXX/XXXX-XX",
  "periodo_apuracao": "MM/AAAA",
  "faturamento_mensal": [{ "mes": "MM/AAAA", "interno": 0.00, "externo": 0.00 }],
  "resumo": {
    "rpa_interno": 0.00, "rpa_externo": 0.00,
    "rbt12_interno": 0.00, "rbt12_externo": 0.00,
    "rba_interno": 0.00, "rba_externo": 0.00,
    "rbaa_interno": 0.00, "rbaa_externo": 0.00
  },
  "tributos": {
    "irpj": 0.00, "csll": 0.00, "cofins": 0.00, "pis": 0.00,
    "inss_cpp": 0.00, "icms": 0.00, "ipi": 0.00, "iss": 0.00, "total": 0.00
  }
}

Instruções:
- Todos os valores devem ser números JavaScript puros com ponto decimal (ex: 10394.70, não "10.394,70").
- faturamento_mensal: leia a seção 2.2.1 (Mercado Interno) e 2.2.2 (Mercado Externo). Inclua o mês do Período de Apuração como último item, usando o valor RPA.
- resumo: seção 2.1 — RPA, RBT12, RBA, RBAA para Mercado Interno e Externo.
- tributos: bloco "Total do Débito Exigível" — IRPJ, CSLL, COFINS, PIS, INSS/CPP, ICMS, IPI, ISS, Total.
- Ordene faturamento_mensal cronologicamente.`
        },
        ...imageContent
      ]
    }],
    temperature: 0,
    response_format: { type: 'json_object' },
    max_tokens: 4096
  });

  const raw = completion.choices[0].message.content;
  const result = JSON.parse(raw);
  console.log(`[VISION] Concluído. total_das=${result.tributos?.total}`);
  return result;
}

app.post('/api/analyze', analyzeLimiter, upload.single('pdf'), async (req, res) => {
  try {
    const { password } = req.body;

    if (!password || password !== process.env.ACCESS_PASSWORD) {
      return res.status(401).json({ error: 'Senha incorreta' });
    }

    if (!req.file) {
      return res.status(400).json({ error: 'Nenhum arquivo PDF enviado' });
    }

    // Valida magic bytes: todo PDF válido começa com "%PDF"
    if (!req.file.buffer.slice(0, 4).toString('ascii').startsWith('%PDF')) {
      return res.status(400).json({ error: 'Arquivo inválido. Envie um PDF genuíno.' });
    }

    // Extract text from PDF buffer (no file saved to disk)
    let pdfText;
    try {
      const pdfData = await pdf(req.file.buffer);
      pdfText = pdfData.text;
      // Texto bruto preservado — a extração numérica trata o formato brasileiro diretamente
    } catch (pdfErr) {
      return res.status(422).json({ error: 'Não foi possível ler o PDF. Verifique se o arquivo não está corrompido.' });
    }

    console.log(`[DEBUG] Texto pós-normalização (primeiros 600 chars):\n${pdfText.slice(0, 600)}\n---`);
    if (!pdfText || pdfText.trim().length < 50) {
      return res.status(422).json({ error: 'O PDF parece estar vazio ou com proteção de cópia.' });
    }

    // Sanitiza o texto antes de inserir no prompt: remove caracteres de controle e trunca
    // para evitar prompt injection via conteúdo malicioso no PDF
    const safePdfText = pdfText
      .replace(/[^\x20-\x7E\xA0-\xFF\n\r\t]/g, ' ')
      .slice(0, 15000);

    const prompt = `Você é um especialista em extrair dados de extratos do Simples Nacional (PGDAS-D) do Brasil.
Analise o texto a seguir e extraia TODOS os dados solicitados. Retorne SOMENTE um JSON válido, sem markdown, sem texto extra.

Estrutura esperada do JSON:
{
  "empresa": "nome empresarial completo",
  "cnpj": "XX.XXX.XXX/XXXX-XX",
  "periodo_apuracao": "MM/AAAA",
  "faturamento_mensal": [
    { "mes": "MM/AAAA", "interno": 0.00, "externo": 0.00 }
  ],
  "resumo": {
    "rpa_interno": 0.00,
    "rpa_externo": 0.00,
    "rbt12_interno": 0.00,
    "rbt12_externo": 0.00,
    "rba_interno": 0.00,
    "rba_externo": 0.00,
    "rbaa_interno": 0.00,
    "rbaa_externo": 0.00
  },
  "tributos": {
    "irpj": 0.00,
    "csll": 0.00,
    "cofins": 0.00,
    "pis": 0.00,
    "inss_cpp": 0.00,
    "icms": 0.00,
    "ipi": 0.00,
    "iss": 0.00,
    "total": 0.00
  }
}

Instruções:
- Este documento pode ser um "Extrato PGDAS-D" ou um "PGDAS-D Declaratório" — ambos possuem as mesmas seções de dados.
- "empresa": use o campo "Nome empresarial".
- "cnpj": use o campo "CNPJ Matriz" (formato XX.XXX.XXX/XXXX-XX).
- "periodo_apuracao": extraia o mês/ano do Período de Apuração (formato MM/AAAA).
- "empresa": use o campo "Nome Empresarial".
- "cnpj": formato XX.XXX.XXX/XXXX-XX.
- "periodo_apuracao": Período de Apuração, formato MM/AAAA.
- Os valores numéricos serão preenchidos por outra rotina — você só precisa extrair empresa, cnpj e periodo_apuracao corretamente. Preencha os demais campos com 0.

TEXTO DO DOCUMENTO:
${safePdfText}`;

    const completion = await openai.chat.completions.create({
      model: 'gpt-4.1-nano',
      messages: [
        { role: 'system', content: 'Você extrai dados de documentos fiscais brasileiros e retorna JSON válido.' },
        { role: 'user', content: prompt }
      ],
      temperature: 0,
      response_format: { type: 'json_object' }
    });

    const rawContent = completion.choices[0].message.content;

    let data;
    try {
      data = JSON.parse(rawContent);
    } catch {
      // Fallback: try to extract JSON from the response
      const match = rawContent.match(/\{[\s\S]*\}/);
      if (match) {
        data = JSON.parse(match[0]);
      } else {
        return res.status(500).json({ error: 'O modelo retornou um formato inesperado. Tente novamente.' });
      }
    }

    // Sobrescreve dados numéricos com extração regex direta do PDF
    // (evita erros de escala no formato Declaratório onde pdf-parse remove vírgulas)
    const regexData = extractNumericalData(pdfText);
    if (regexData.faturamento_mensal) {
      // Adiciona o PA atual como último item (usando RPA do resumo regex ou AI)
      const rpaInt = regexData.resumo?.rpa_interno ?? data.resumo?.rpa_interno ?? 0;
      const rpaExt = regexData.resumo?.rpa_externo ?? data.resumo?.rpa_externo ?? 0;
      const pa = data.periodo_apuracao;
      const alreadyHasPA = regexData.faturamento_mensal.some(r => r.mes === pa);
      if (pa && !alreadyHasPA) regexData.faturamento_mensal.push({ mes: pa, interno: rpaInt, externo: rpaExt });
      data.faturamento_mensal = regexData.faturamento_mensal;
    }
    if (regexData.resumo) data.resumo = regexData.resumo;
    if (regexData.tributos) data.tributos = regexData.tributos;
    console.log(`[REGEX] faturamento_mensal: ${regexData.faturamento_mensal ? regexData.faturamento_mensal.length + ' meses' : 'não extraído'} | resumo: ${regexData.resumo ? 'ok' : 'não extraído'} | tributos: ${regexData.tributos ? 'ok' : 'não extraído'}`);

    // Fallback: se total_das <= 1000, os valores provavelmente estão errados — usa gpt-4o vision
    const totalDas = data.tributos?.total ?? 0;
    let visionUsed = false;
    if (totalDas <= 1000) {
      console.log(`[VISION] total_das=${totalDas} <= 1000, ativando fallback por visão`);
      try {
        const visionData = await extractWithVision(req.file.buffer);
        if ((visionData.tributos?.total ?? 0) > totalDas) {
          Object.assign(data, visionData);
          visionUsed = true;
          console.log(`[VISION] Substituído. Novo total_das=${data.tributos?.total}`);
        }
      } catch (visionErr) {
        console.error('[VISION] Falha na extração por visão:', visionErr.message);
      }
    }

    const ts = new Date().toISOString();
    saveToHistory({ id: crypto.randomBytes(6).toString('hex'), ts, empresa: data.empresa || '—', cnpj: data.cnpj || '—', periodo: data.periodo_apuracao || '—', total_das: data.tributos?.total ?? null, data });
    console.log(JSON.stringify({ reqId: req.reqId, ts, status: 'ok' }));
    // vision_used enviado na resposta mas NÃO salvo no histórico
    res.json({ ...data, vision_used: visionUsed });

  } catch (err) {
    console.error(JSON.stringify({ reqId: req.reqId, ts: new Date().toISOString(), path: req.path, error: err.message, code: err.code }));
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({ error: 'Arquivo muito grande. Máximo: 1 MB.' });
    }
    res.status(500).json({ error: 'Erro interno ao processar o arquivo. Tente novamente.' });
  }
});

app.get('/api/fipe/saldo', async (req, res) => {
  const password = req.headers['x-password'];
  if (!password || password !== process.env.ACCESS_PASSWORD) {
    return res.status(401).json({ error: 'Senha incorreta' });
  }
  try {
    const apiRes = await fetch('https://gateway.apibrasil.io/api/v2/balance', {
      headers: { 'Authorization': `Bearer ${process.env.APIBRASIL_TOKEN}` }
    });
    const data = await apiRes.json();
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao buscar saldo.' });
  }
});

// até 10 consultas FIPE por IP a cada 60 segundos
const fipeLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Muitas consultas. Aguarde 1 minuto.' }
});

app.post('/api/fipe', fipeLimiter, async (req, res) => {
  const { password, placa } = req.body;

  if (!password || password !== process.env.ACCESS_PASSWORD) {
    return res.status(401).json({ error: 'Senha incorreta' });
  }

  if (!placa || typeof placa !== 'string') {
    return res.status(400).json({ error: 'Informe a placa do veículo.' });
  }

  const cleanPlaca = placa.replace(/[^a-zA-Z0-9]/g, '').toUpperCase();
  if (cleanPlaca.length < 6 || cleanPlaca.length > 8) {
    return res.status(400).json({ error: 'Placa inválida. Use o formato ABC1234 ou ABC1D23.' });
  }

  try {
    const apiRes = await fetch('https://gateway.apibrasil.io/api/v2/consulta/veiculos/credits', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.APIBRASIL_TOKEN}`
      },
      body: JSON.stringify({ tipo: 'fipe', placa: cleanPlaca, homolog: false })
    });

    const apiData = await apiRes.json();

    if (apiData.error) {
      return res.status(502).json({ error: apiData.message || 'Erro na consulta FIPE.' });
    }

    res.json(apiData);
  } catch (err) {
    console.error('[FIPE]', err.message);
    res.status(500).json({ error: 'Erro ao consultar FIPE. Tente novamente.' });
  }
});

// ── Fragmentador de PDF ────────────────────────────────────────
const splitUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 20 * 1024 * 1024 }, // 20 MB
  fileFilter: (_req, file, cb) => {
    if (file.mimetype === 'application/pdf') cb(null, true);
    else cb(new Error('Apenas arquivos PDF são aceitos'));
  }
});

const splitLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Muitas requisições de fragmentação. Aguarde 1 minuto.' }
});

app.post('/api/split-pdf', splitLimiter, splitUpload.single('pdf'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Nenhum PDF enviado.' });

  const MAX_PAGES = 50;

  try {
    const pdfDoc = await PDFDocument.load(req.file.buffer);
    const totalPages = pdfDoc.getPageCount();

    if (totalPages > MAX_PAGES) {
      return res.status(400).json({ error: `PDF tem ${totalPages} páginas. O limite é ${MAX_PAGES}.` });
    }

    const baseName = req.file.originalname.replace(/\.pdf$/i, '').replace(/[^\w\-]/g, '_');
    const pad = String(totalPages).length;

    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', `attachment; filename="${baseName}_paginas.zip"`);

    const archive = archiver('zip', { zlib: { level: 6 } });
    archive.pipe(res);

    for (let i = 0; i < totalPages; i++) {
      const singleDoc = await PDFDocument.create();
      const [page] = await singleDoc.copyPages(pdfDoc, [i]);
      singleDoc.addPage(page);
      const bytes = await singleDoc.save();
      const pageNum = String(i + 1).padStart(pad, '0');
      archive.append(Buffer.from(bytes), { name: `pagina_${pageNum}.pdf` });
    }

    await archive.finalize();
  } catch (err) {
    console.error('[SPLIT-PDF]', err.message);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Erro ao fragmentar o PDF. Verifique se o arquivo é válido.' });
    }
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✓ Servidor rodando em http://localhost:${PORT}`);
});
