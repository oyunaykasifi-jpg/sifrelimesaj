// sifrelimesaj.com - Offline, client-side
// Tek blokta: metin + (opsiyonel) fotoğraf
// Şifreleme: AES-256-GCM, anahtar türetme: PBKDF2(SHA-256)
// Format: GSM1.<salt>.<iv>.<ct> (Base64URL)

const VERSION = "GSM1";
const PBKDF2_ITERS = 200_000;
const SALT_LEN = 16;
const IV_LEN = 12;

const $ = (id) => document.getElementById(id);

function b64urlEncode(bytes) {
  let bin = "";
  bytes.forEach((b) => (bin += String.fromCharCode(b)));
  const b64 = btoa(bin);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function b64urlDecode(str) {
  const pad = str.length % 4 === 0 ? "" : "=".repeat(4 - (str.length % 4));
  const b64 = (str + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function toUtf8Bytes(s) {
  return new TextEncoder().encode(s);
}
function fromUtf8Bytes(b) {
  return new TextDecoder().decode(b);
}

async function deriveKeyFromPass(pass, salt) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    toUtf8Bytes(pass),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERS, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptBytes(plainBytes, pass) {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
  const key = await deriveKeyFromPass(pass, salt);

  const ctBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plainBytes);
  const ct = new Uint8Array(ctBuf);
  return `${VERSION}.${b64urlEncode(salt)}.${b64urlEncode(iv)}.${b64urlEncode(ct)}`;
}

async function decryptBytes(token, pass) {
  const parts = token.trim().split(".");
  if (parts.length !== 4 || parts[0] !== VERSION) {
    throw new Error("Format hatalı. GSM1.*.*.* bekleniyor.");
  }
  const salt = b64urlDecode(parts[1]);
  const iv = b64urlDecode(parts[2]);
  const ct = b64urlDecode(parts[3]);

  const key = await deriveKeyFromPass(pass, salt);
  const ptBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return new Uint8Array(ptBuf);
}

// --- Paketleme: JSON header + binary foto (opsiyonel) ---
// Binary paket:
// [magic "PK1"(3)] [hdrLen u32 LE (4)] [hdr JSON bytes] [photoBytes?]
function u32ToBytesLE(n) {
  const a = new Uint8Array(4);
  const dv = new DataView(a.buffer);
  dv.setUint32(0, n, true);
  return a;
}
function bytesToU32LE(b, off) {
  return new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(off, true);
}
function concatBytes(...arrs) {
  const total = arrs.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const a of arrs) {
    out.set(a, o);
    o += a.length;
  }
  return out;
}

async function buildPayload(plainText, photoFile) {
  const header = { t: plainText || "" };

  let photoBytes = null;
  if (photoFile) {
    const buf = await photoFile.arrayBuffer();
    photoBytes = new Uint8Array(buf);
    header.p = {
      mime: photoFile.type || "application/octet-stream",
      len: photoBytes.length,
    };
  }

  const hdrBytes = toUtf8Bytes(JSON.stringify(header));
  const magic = toUtf8Bytes("PK1");
  const hdrLen = u32ToBytesLE(hdrBytes.length);

  return photoBytes
    ? concatBytes(magic, hdrLen, hdrBytes, photoBytes)
    : concatBytes(magic, hdrLen, hdrBytes);
}

function parsePayload(payloadBytes) {
  const magic = fromUtf8Bytes(payloadBytes.slice(0, 3));
  if (magic !== "PK1") throw new Error("Payload magic hatalı.");

  const hdrLen = bytesToU32LE(payloadBytes, 3);
  const hdrStart = 7;
  const hdrEnd = hdrStart + hdrLen;
  if (hdrEnd > payloadBytes.length) throw new Error("Header uzunluğu bozuk.");

  const hdr = JSON.parse(fromUtf8Bytes(payloadBytes.slice(hdrStart, hdrEnd)));
  const photo = hdr.p ? payloadBytes.slice(hdrEnd, hdrEnd + hdr.p.len) : null;

  return { text: hdr.t || "", photoMime: hdr.p?.mime || null, photoBytes: photo };
}

// --- Anahtar üretimi (kısa & okunabilir) ---
const WORDS_TR = [
  "mavi",
  "deniz",
  "kutup",
  "rüzgar",
  "güneş",
  "çınar",
  "papatya",
  "gece",
  "kum",
  "ada",
  "yıldız",
  "nehir",
  "bulut",
  "martı",
  "dalg",
  "kıvılcım",
  "ay",
  "sahil",
  "orman",
  "vadi",
];
function randInt(max) {
  return crypto.getRandomValues(new Uint32Array(1))[0] % max;
}
function cap(s) {
  return s.charAt(0).toUpperCase() + s.slice(1);
}
function genShortKey() {
  const w1 = WORDS_TR[randInt(WORDS_TR.length)];
  const w2 = WORDS_TR[randInt(WORDS_TR.length)];
  const n = String(randInt(100)).padStart(2, "0");
  const letters = "abcdefghjkmnpqrstuvwxyz";
  const l1 = letters[randInt(letters.length)];
  const l2 = letters[randInt(letters.length)];
  return `${cap(w1)}${cap(w2)}${n}${l1}${l2}`;
}

function estimateStrength(key) {
  const k = (key || "").trim();
  if (!k) return { level: "-", cls: "", hint: "" };
  let score = 0;
  if (k.length >= 8) score += 1;
  if (k.length >= 12) score += 1;
  if (/[a-z]/.test(k)) score += 1;
  if (/[A-Z]/.test(k)) score += 1;
  if (/[0-9]/.test(k)) score += 1;
  if (/[^a-zA-Z0-9]/.test(k)) score += 1;

  if (k.length < 8 || score <= 2)
    return { level: "Zayıf", cls: "err", hint: "Daha güçlü anahtar için 🔑 Üret kullan." };
  if (score <= 4) return { level: "Orta", cls: "warn", hint: "İdare eder. Daha güçlü için 🔑 Üret." };
  return {
    level: "Güçlü",
    cls: "ok",
    hint: "Harika. Anahtarı mümkünse WhatsApp dışında paylaş.",
  };
}

function setTab(isLock) {
  $("panelLock").style.display = isLock ? "block" : "none";
  $("panelUnlock").style.display = isLock ? "none" : "block";
  $("tabLock").classList.toggle("primary", isLock);
  $("tabUnlock").classList.toggle("primary", !isLock);
}

function updateStrengthUI() {
  const s = estimateStrength($("key").value);
  $("strengthPill").textContent = `Güç: ${s.level}`;
  $("strengthPill").className = `pill ${s.cls || ""}`;
  $("strengthHint").textContent = s.hint || "";
}

async function copyToClipboard(text) {
  await navigator.clipboard.writeText(text);
}

function downloadText(filename, text) {
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

function downloadBlob(filename, blob) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

function extFromMime(mime) {
  const m = (mime || "").toLowerCase();
  if (m.includes("png")) return "png";
  if (m.includes("jpeg") || m.includes("jpg")) return "jpg";
  if (m.includes("webp")) return "webp";
  if (m.includes("gif")) return "gif";
  return "bin";
}

async function shareText(title, text) {
  if (navigator.share) {
    await navigator.share({ title, text });
    return true;
  }
  return false;
}

let lastImgBlob = null;
let lastImgUrl = null;
let lastImgMime = null;

function registerSW() {
  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("./sw.js").catch(() => {});
  }
}

// --- Events ---
$("tabLock").onclick = () => setTab(true);
$("tabUnlock").onclick = () => setTab(false);

$("genKey").onclick = () => {
  $("key").value = genShortKey();
  updateStrengthUI();
};
$("key").addEventListener("input", updateStrengthUI);

$("lockBtn").onclick = async () => {
  try {
    $("lockStatus").textContent = "";
    const text = $("plain").value || "";
    const file = $("photo").files?.[0] || null;
    const key = $("key").value.trim();

    if (!key) return ($("lockStatus").textContent = "Anahtar boş olamaz (🔑 Üret).");
    if (!text.trim() && !file) return ($("lockStatus").textContent = "En az metin veya fotoğraf eklemelisin.");

    // büyük fotoğraflar WhatsApp’a yapıştırılacak blokları aşırı büyütür
    if (file && file.size > 800_000) {
      $("lockStatus").textContent =
        "Uyarı: Fotoğraf büyük. Blok çok uzayabilir. İstersen daha küçük bir foto seç.";
      // devam etsin, engellemiyoruz
    }

    const payload = await buildPayload(text, file);
    const token = await encryptBytes(payload, key);

    $("cipher").value = token;
    $("lockStatus").textContent = "Hazır ✅ (WhatsApp’ta en garanti: Belge/Doküman)";
  } catch (e) {
    $("lockStatus").textContent = `Hata: ${e.message || e}`;
  }
};

$("copyCipher").onclick = async () => {
  const t = $("cipher").value.trim();
  if (!t) return;
  try {
    await copyToClipboard(t);
    $("lockStatus").textContent = "Kopyalandı ✅";
  } catch {
    $("lockStatus").textContent = "Kopyalanamadı (izin).";
  }
};

const shareCipherBtn = document.getElementById("shareCipher");
if (shareCipherBtn) {
  shareCipherBtn.onclick = async () => {
    const t = $("cipher").value.trim();
    if (!t) return;
    try {
      const ok = await shareText("Şifreli Mesaj", t);
      if (!ok) {
        await copyToClipboard(t);
        $("lockStatus").textContent = "Paylaş yoktu, kopyalandı ✅";
      } else {
        $("lockStatus").textContent = "Paylaşıma hazır ✅";
      }
    } catch {
      $("lockStatus").textContent = "Paylaşım iptal/başarısız.";
    }
  };
}

$("downloadCipher").onclick = () => {
  const t = $("cipher").value.trim();
  if (!t) return;
  downloadText("sifreli-blok.txt", t);
  $("lockStatus").textContent = "Dosya indirildi ✅";
};

$("clearLock").onclick = () => {
  $("plain").value = "";
  $("photo").value = "";
  $("cipher").value = "";
  $("lockStatus").textContent = "";
};

$("unlockBtn").onclick = async () => {
  try {
    $("unlockStatus").textContent = "";
    $("plainOut").value = "";
    $("imgWrap").style.display = "none";
    lastImgBlob = null;
    lastImgMime = null;

    // önceki URL varsa temizle
    if (lastImgUrl) {
      URL.revokeObjectURL(lastImgUrl);
      lastImgUrl = null;
    }

    const token = $("cipherIn").value.trim();
    const key = $("keyIn").value.trim();
    if (!token) return ($("unlockStatus").textContent = "Şifreli blok boş olamaz.");
    if (!key) return ($("unlockStatus").textContent = "Anahtar boş olamaz.");

    const payloadBytes = await decryptBytes(token, key);
    const parsed = parsePayload(payloadBytes);

    $("plainOut").value = parsed.text || "";

    if (parsed.photoBytes && parsed.photoMime) {
      lastImgMime = parsed.photoMime;
      lastImgBlob = new Blob([parsed.photoBytes], { type: parsed.photoMime });
      lastImgUrl = URL.createObjectURL(lastImgBlob);
      $("imgOut").src = lastImgUrl;
      $("imgWrap").style.display = "block";
    }

    $("unlockStatus").textContent = "Çözüldü ✅";
  } catch (e) {
    $("unlockStatus").textContent = `Açılamadı: ${e.message || e}`;
  }
};

$("downloadImg").onclick = () => {
  if (!lastImgBlob) return;
  const ext = extFromMime(lastImgMime);
  downloadBlob(`cozulmus-foto.${ext}`, lastImgBlob);
};

$("copyPlain").onclick = async () => {
  const t = $("plainOut").value.trim();
  if (!t) return;
  try {
    await copyToClipboard(t);
    $("unlockStatus").textContent = "Metin kopyalandı ✅";
  } catch {
    $("unlockStatus").textContent = "Kopyalanamadı (izin).";
  }
};

const sharePlainBtn = document.getElementById("sharePlain");
if (sharePlainBtn) {
  sharePlainBtn.onclick = async () => {
    const t = $("plainOut").value.trim();
    if (!t) return;
    try {
      const ok = await shareText("Çözülen Mesaj", t);
      if (!ok) {
        await copyToClipboard(t);
        $("unlockStatus").textContent = "Paylaş yoktu, kopyalandı ✅";
      } else {
        $("unlockStatus").textContent = "Paylaşıma hazır ✅";
      }
    } catch {
      $("unlockStatus").textContent = "Paylaşım iptal/başarısız.";
    }
  };
}

$("clearUnlock").onclick = () => {
  $("cipherIn").value = "";
  $("keyIn").value = "";
  $("plainOut").value = "";
  $("imgWrap").style.display = "none";
  $("unlockStatus").textContent = "";

  if (lastImgUrl) {
    URL.revokeObjectURL(lastImgUrl);
    lastImgUrl = null;
  }
  lastImgBlob = null;
  lastImgMime = null;
};

// Donate kopyalama
const donateBtn = document.getElementById("copyDonate");
if (donateBtn) {
  donateBtn.onclick = async () => {
    try {
      const addr = document.getElementById("donateAddr").value;
      await navigator.clipboard.writeText(addr);
      document.getElementById("donateStatus").textContent = "Kopyalandı ✅";
    } catch {
      document.getElementById("donateStatus").textContent = "Kopyalanamadı (izin).";
    }
  };
}

function toggleHow() {
  const box = document.getElementById("howBox");
  box.style.display = box.style.display === "none" ? "block" : "none";
}

// init
updateStrengthUI();
registerSW();