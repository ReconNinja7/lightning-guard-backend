// backend/server.js
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import multer from "multer";
import mammoth from "mammoth";
import Tesseract from "tesseract.js";
import fsPromises from "fs/promises";
import path from "path";
import os from "os";
import { GoogleGenerativeAI } from "@google/generative-ai";

dotenv.config();

const app = express();

app.use(cors({
  origin: "https://lightning-guard.web.app",
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type"]
}));

app.options("*", cors());

app.use(express.json());

const upload = multer({ storage: multer.memoryStorage() });

if (!process.env.GEMINI_API_KEY) {
  console.warn("⚠️ GEMINI_API_KEY not set in .env — set GEMINI_API_KEY to call Gemini.");
}
const genAI = new GoogleGenerativeAI({
  apiKey: process.env.GEMINI_API_KEY,
  apiEndpoint: "https://generativelanguage.googleapis.com/v1"   // 👈 force v1
});
let GEMINI_MODEL = process.env.GEMINI_MODEL || "gemini-1.5-flash-latest";
function getModel() {
  return genAI.getGenerativeModel({ model: GEMINI_MODEL });
}

const clamp = (n, a = 0, b = 100) => Math.max(a, Math.min(b, n));

function classifyThreatLevel(confidence) {
  if (confidence >= 70) return "danger";
  if (confidence >= 40) return "warning";
  return "safe";
}

function guessCategoryFromText(text) {
  const t = (text || "").toLowerCase();
  if (/\b(phish|phishing|credential|login|password|verify|suspended|account)\b/.test(t)) return "Phishing";
  if (/\b(malware|trojan|ransomware|virus|exploit)\b/.test(t)) return "Malware";
  if (/\b(scams|fraud|donation|payment)\b/.test(t)) return "Fraud";
  if (/\b(spam)\b/.test(t)) return "Spam";
  return "Uncategorized";
}

const SECTION_NAMES = [
  "Analysis Details",
  "Key Findings",
  "Security Recommendations",
  "Services",
  "Threat Category",
  "Confidence Score",
  "Short Explanation",
];

function extractSection(text, name) {
  if (!text) return "";
  const safeNames = SECTION_NAMES.map(s => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|");
  const pattern = new RegExp(`${name}\\s*:\\s*([\\s\\S]*?)(?:\\n\\s*(?:${safeNames})\\s*:|$)`, "i");
  const m = text.match(pattern);
  return m ? m[1].trim() : "";
}

function parseBulletLines(block) {
  if (!block) return [];
  const lines = block
    .split(/\r?\n/)
    .map(s => s.trim())
    .filter(Boolean)
    .map(s => s.replace(/^[-•*]\s*/, ""))
    .map(s => s.replace(/^\d+\s*[.)]\s*/, ""))
    .map(s => s.trim())
    .filter(Boolean);

  if (lines.length <= 1 && / - /.test(block)) {
    return block.split(/ - /).map(s => s.trim()).filter(Boolean);
  }
  return lines;
}

function parseConfidenceFromText(text) {
  if (!text) return null;
  const pct = text.match(/(\d{1,3}(?:\.\d+)?)\s*%/i);
  if (pct) return clamp(Math.round(Number(pct[1])));
  const num = text.match(/(\d{1,3}(?:\.\d+)?)(?=\s*(?:percent|percentage))/i);
  if (num) return clamp(Math.round(Number(num[1])));
  const conf = text.match(/confidence[^0-9]*?(\d{1,3}(?:\.\d+)?)/i);
  if (conf) return clamp(Math.round(Number(conf[1])));
  return null;
}

function heuristicConfidence(text) {
  const t = (text || "").toLowerCase();
  let score = 4; 

  const keywords = [
    "login","password","verify","urgent","suspended","bank","account",
    "credit","ssn","click","reset","payment","confirm","credential"
  ];

  let hits = 0;
  for (const k of keywords) {
    if (t.includes(k)) hits++;
  }
  score += Math.min(36, hits * 6); 

  const urlHits = (t.match(/https?:\/\/[^\s]+/g) || []).length;
  score += Math.min(30, urlHits * 8); // up to +30

  if (t.length > 1200) score += 5;
  else if (t.length > 600) score += 2;

  const normalized = Math.round(score * 0.88);
  return clamp(normalized, 0, 100);
}

function extractRawTextFromResult(result) {
  try {
    if (!result) return "";
    if (result?.response && typeof result.response.text === "function") {
      return result.response.text();
    }
    if (result?.response?.candidates?.[0]?.content?.parts?.[0]?.text) {
      return result.response.candidates[0].content.parts[0].text;
    }
    return typeof result === "string" ? result : JSON.stringify(result);
  } catch (e) {
    return String(result ?? "");
  }
}

async function extractTextFromFileObject(file) {
  const { originalname = "", buffer, mimetype = "" } = file;
  const nameLower = (originalname || "").toLowerCase();

  try {
    // DOCX
    if (
      mimetype === "application/vnd.openxmlformats-officedocument.wordprocessingml.document" ||
      nameLower.endsWith(".docx")
    ) {
      try {
        const res = await mammoth.extractRawText({ buffer });
        return (res?.value || "").trim();
      } catch (e) {
        console.warn("mammoth error:", e?.message || e);
        return "";
      }
    }

    // Plain text / txt
    if (mimetype.startsWith("text/") || nameLower.endsWith(".txt")) {
      try {
        return buffer.toString("utf-8").trim();
      } catch (e) {
        return "";
      }
    }

    if (mimetype.startsWith("image/") || nameLower.match(/\.(png|jpe?g|bmp|webp)$/)) {
      const ext = path.extname(originalname) || ".png";
      const tmpName = `lg_${Date.now()}_${Math.random().toString(36).slice(2)}${ext}`;
      const tmpPath = path.join(os.tmpdir(), tmpName);
      try {
        await fsPromises.writeFile(tmpPath, buffer);
        const ocrRes = await Tesseract.recognize(tmpPath, "eng");
        const txt = ocrRes?.data?.text || "";
        return txt.trim();
      } catch (e) {
        console.warn("OCR failed for", originalname, e?.message || e);
        return "";
      } finally {
        try { await fsPromises.unlink(tmpPath); } catch {}
      }
    }

    if (mimetype === "application/pdf" || nameLower.endsWith(".pdf")) {
      return "";
    }

    try {
      return buffer.toString("utf-8").trim();
    } catch (e) {
      return "";
    }
  } catch (err) {
    console.error("extractTextFromFileObject unexpected:", err);
    return "";
  }
}

function MASTER_PROMPT(textToAnalyze) {
  return `
You are a professional cybersecurity analyst. Analyze the text below and respond EXACTLY with the sections shown (plain text only).

Important: Choose a CALIBRATED numeric "Confidence Score" (0-100) that reflects the actual likelihood of maliciousness:
- Avoid returning high numbers by default.
- If content is likely benign, give a low confidence (e.g., 0-30).
- If content is ambiguous, give moderate confidence (e.g., 30-60).
- If strongly phishing/malicious with clear URLs, urgent statements, leaked credentials etc., give high confidence (70+).
- Return a single integer (no % sign, no decimals).

Structure exactly (no extra commentary):

Analysis Details:
  One short paragraph (1-3 sentences) — no bullets.

Key Findings:
  - Use hyphen + space for each line. If none, write: None

Security Recommendations:
  - Use hyphen + space for each line. If none, write: None

Services:
  - Always suggest 2–3 real-world services or indian authorities users can report threats to with links
    (e.g., CERT-In, Anti-Phishing Working Group, local cybercrime reporting portal).
  - If truly irrelevant, write "None".

Threat Category:
  One word: Phishing, Scam, Malware, Fraud, Spam, Other, Uncategorized

Confidence Score:
  A single integer 0-100 (no percent sign)

Short Explanation:
  One short single-sentence summary.

Text to analyze:
${textToAnalyze}
`.trim();
}

async function analyzePromptAndReturnStructured(prompt) {
  const model = getModel();
  const result = await model.generateContent({
    contents: [{ role: "user", parts: [{ text: prompt }] }],
    generationConfig: { temperature: 0.2 }
  });

  const raw = extractRawTextFromResult(result);
  console.log("=== Gemini raw output ===\n", raw, "\n=== end raw ===");

  let parsed = null;
  try { parsed = JSON.parse(raw); } catch (_) { parsed = null; }

  let confidence = null;
  let explanation = null;
  let next_steps = null;

  if (parsed && typeof parsed === "object") {
    confidence = parsed.confidence ?? parsed.confidence_score ?? parsed.score ?? parsed.confidencePercent;
    explanation = parsed.explanation ?? parsed.reasoning ?? parsed.details ?? parsed.summary ?? "";
    next_steps = parsed.key_findings ?? parsed.keyFindings ?? parsed.recommendations ?? parsed.next_steps ?? parsed.actions ?? parsed.advice ?? parsed.suggestions;
  }

  if (typeof confidence === "string") {
    const nm = confidence.match(/(\d{1,3}(?:\.\d+)?)/);
    confidence = nm ? clamp(Math.round(Number(nm[1]))) : null;
  }
  if (typeof confidence === "number") confidence = clamp(Math.round(confidence));

  const detailsSection = extractSection(raw, "Analysis Details");
  const keyFindingsSection = extractSection(raw, "Key Findings");
  const secRecsSection = extractSection(raw, "Security Recommendations");
  const servicesSection = extractSection(raw, "Services");
  const confSection = extractSection(raw, "Confidence Score");
  const shortExplanation = extractSection(raw, "Short Explanation");
  const categorySection = extractSection(raw, "Threat Category");

const confFromSection = parseConfidenceFromText(confSection);
if (confFromSection != null) {
  confidence = confFromSection;
}

if (confidence == null) {
  const extracted = parseConfidenceFromText(raw);
  if (extracted != null) confidence = extracted;
}

let parsedConfidence = null;
if (parsed && (parsed.confidence || parsed.score || parsed.confidence_score || parsed.confidencePercent)) {
  const cand = parsed.confidence ?? parsed.score ?? parsed.confidence_score ?? parsed.confidencePercent;
  const num = Number(cand);
  if (Number.isFinite(num)) parsedConfidence = clamp(Math.round(num), 0, 100);
}

const heuristic = heuristicConfidence(raw + (explanation || ""));

if (confidence == null) {
  if (parsedConfidence != null) {
    let combined = Math.round(parsedConfidence * 0.7 + heuristic * 0.3);

    if (parsedConfidence - heuristic > 40) {
      const gap = parsedConfidence - heuristic;
      combined = Math.round(heuristic + Math.min(30, Math.round(gap * 0.25)));
    }

    confidence = clamp(combined, 0, 100);

    if (parsedConfidence >= 90 && heuristic <= 30) {
      console.warn("Model high confidence vs heuristic -- parsed:", parsedConfidence, "heuristic:", heuristic);
    }
  } else {
    confidence = heuristic;
  }
}

confidence = clamp(Number.isFinite(Number(confidence)) ? Math.round(Number(confidence)) : heuristic, 0, 100);

  const details = detailsSection || shortExplanation || explanation || (raw || "").slice(0, 600);

  let keyFindings = parseBulletLines(keyFindingsSection);
  if (!keyFindings.length) {
    if (Array.isArray(next_steps)) keyFindings = next_steps.map(String);
    else if (typeof next_steps === "string") keyFindings = parseBulletLines(next_steps);
    else keyFindings = [];
  }

  const securityRecommendationsLines = parseBulletLines(secRecsSection);
  const servicesLines = parseBulletLines(servicesSection);

  const explicitCategory = categorySection || (parsed && (parsed["Threat Category"] || parsed.category));
  const categoryText = explicitCategory ? explicitCategory.split(/\r?\n/)[0].trim() : null;
  const category = (categoryText && categoryText !== "") ? categoryText : guessCategoryFromText(raw || details);

  const final = {
    threatLevel: classifyThreatLevel(Number(confidence ?? 0)),
    confidence: clamp(Number(confidence ?? 0)),
    category,
    details,
    recommendations: keyFindings,
    securityRecommendations: securityRecommendationsLines.join("\n") || "None",
    services: servicesLines.join("\n") || "None",
    rawModelOutput: raw
  };

  return final;
}

app.get("/api/health", (req, res) => {
  res.json({ ok: true, service: "Lightning Guard Backend (no pdf-parse)", model: GEMINI_MODEL });
});

app.post("/api/analyze-text", async (req, res) => {
  try {
    const { text } = req.body;
    if (!text || !String(text).trim()) return res.status(400).json({ error: "No text provided" });

    const prompt = MASTER_PROMPT(String(text).trim());
    const final = await analyzePromptAndReturnStructured(prompt);
    return res.json({ ok: true, result: final, ...final });
  } catch (err) {
    console.error("Error in /api/analyze-text:", err);
    if (err?.status === 429 && GEMINI_MODEL !== "gemini-1.5-flash-latest") {
      GEMINI_MODEL = "gemini-1.5-flash-latest";
      return res.status(503).json({ ok: false, error: "Quota exceeded on PRO, switched to FLASH. Retry shortly." });
    }
    console.error("Error in /api/analyze-text:", err?.message || err);
return res.status(500).json({ error: err?.message || "Failed to analyze text" });
  }
});

app.post("/api/analyze-file", upload.array("files"), async (req, res) => {
  try {
    const textInput = (req.body.text || "").toString();
    const files = req.files || [];

    if (!textInput && (!files || files.length === 0)) {
      return res.status(400).json({ error: "No text or files provided" });
    }

    let extractedText = "";
    for (const file of files) {
      try {
        const t = await extractTextFromFileObject(file);
        if (t && String(t).trim()) {
          extractedText += `\n[File: ${file.originalname}]\n${t}\n`;
        } else {
          extractedText += `\n[File: ${file.originalname}] (no text extracted - supported: DOCX, TXT, IMAGE)\n`;
        }
      } catch (e) {
        console.warn("extractTextFromFileObject failed for", file.originalname, e?.message || e);
        extractedText += `\n[File: ${file.originalname}] (error during extraction)\n`;
      }
    }

    const finalText = (textInput + "\n" + extractedText).trim();
    if (!finalText) return res.status(400).json({ error: "No readable text extracted from input or files" });

    const MAX_INPUT = 16000;
    const safeText = finalText.length > MAX_INPUT ? (finalText.slice(0, MAX_INPUT) + "\n[TRUNCATED]") : finalText;

    const prompt = MASTER_PROMPT(safeText);
    const final = await analyzePromptAndReturnStructured(prompt);
    return res.json({ ok: true, result: final, ...final });
  } catch (err) {
    console.error("Error in /api/analyze-file:", err);
    return res.status(500).json({ error: "Failed to analyze file(s)" });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`⚡ Backend running at http://localhost:${PORT}`);
});
