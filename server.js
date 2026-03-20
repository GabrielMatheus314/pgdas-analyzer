require('dotenv').config();
const express = require('express');
const multer = require('multer');
const pdf = require('pdf-parse');
const OpenAI = require('openai');
const path = require('path');

const app = express();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 20 * 1024 * 1024 }, // 20 MB
  fileFilter: (_req, file, cb) => {
    if (file.mimetype === 'application/pdf') cb(null, true);
    else cb(new Error('Apenas arquivos PDF são aceitos'));
  }
});

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.post('/api/analyze', upload.single('pdf'), async (req, res) => {
  try {
    const { password } = req.body;

    if (!password || password !== process.env.ACCESS_PASSWORD) {
      return res.status(401).json({ error: 'Senha incorreta' });
    }

    if (!req.file) {
      return res.status(400).json({ error: 'Nenhum arquivo PDF enviado' });
    }

    // Extract text from PDF buffer (no file saved to disk)
    let pdfText;
    try {
      const pdfData = await pdf(req.file.buffer);
      pdfText = pdfData.text;
    } catch (pdfErr) {
      return res.status(422).json({ error: 'Não foi possível ler o PDF. Verifique se o arquivo não está corrompido.' });
    }

    if (!pdfText || pdfText.trim().length < 50) {
      return res.status(422).json({ error: 'O PDF parece estar vazio ou com proteção de cópia.' });
    }

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
- "faturamento_mensal": extraia da seção "2.2) Receitas Brutas Anteriores" todos os meses listados (Mercado Interno e Externo). Inclua também o período atual de apuração (PA) como último item.
- "resumo": extraia da seção "2.1 Discriminativo de Receitas" (RPA, RBT12, RBA, RBAA).
- "tributos": use os valores da seção "4) Total Geral da Empresa > Total do Débito Exigível".
- Use ponto como separador decimal nos números (ex: 25316.70).
- Ordene faturamento_mensal cronologicamente do mais antigo para o mais recente.

TEXTO DO EXTRATO:
${pdfText}`;

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

    res.json(data);

  } catch (err) {
    console.error('[ERROR]', err.message);
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({ error: 'Arquivo muito grande. Máximo: 20 MB.' });
    }
    res.status(500).json({ error: 'Erro interno ao processar o arquivo. Tente novamente.' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✓ Servidor rodando em http://localhost:${PORT}`);
});
