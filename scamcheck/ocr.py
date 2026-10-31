"""Screenshot -> text/QR -> scamcheck.

Three-tier OCR fallback chain (first available wins):
1. macOS native Apple Vision framework (zero install, JXA bridge)
2. Tesseract (if installed, e.g. brew install tesseract; `brew install
   tesseract-lang` adds Hindi/Marathi/Tamil/... packs which are picked
   up automatically via --list-langs)
3. AI vision model (only if OPENAI_API_KEY / OPENAI_BASE_URL set)

Languages: this machine's Apple Vision lists hi-IN as "supported" but
has no usable Devanagari model (real-Devanagari probes OCR as garbage),
so Hindi/Hinglish screenshots ride on tesseract packs or the AI tier.
English OCR is unaffected.

Then the extracted text flows into the normal analyzer, with the
conversation-trajectory engine auto-engaging for multi-line chat screens.

QR codes in screenshots are decoded separately with Vision
(`detect_qr`), so a link hidden behind a QR is analyzed like any other link.

Note: `osascript -l JavaScript -` (script via stdin) segfaults on some macOS
versions when arguments follow ' -- ', so all JXA sources are cached to
temp files and passed to osascript by path.
"""

import base64
import json
import os
import shutil
import subprocess
import tempfile

# ---------------------------------------------------------------------------
# Tier 1: macOS Apple Vision (JXA -> VNRecognizeTextRequest). Works on any
# macOS 10.15+, no third-party installs.
# ---------------------------------------------------------------------------

JXA_OCR = """
ObjC.import('Vision')
ObjC.import('AppKit')
function run(argv) {
  var path = argv[0]
  var url = $.NSURL.fileURLWithPath(path)
  var handler = $.VNImageRequestHandler.alloc.initWithURLOptions(url, $.NSDictionary.dictionary)
  var req = $.VNRecognizeTextRequest.alloc.init
  req.recognitionLevel = 1  // accurate
  req.usesLanguageCorrection = false
  var err = Ref()
  handler.performRequestsError($.NSArray.arrayWithObject(req), err)
  if (err[0] && !err[0].isNil()) return ''
  var res = req.results
  if (!res) return ''
  var obsArr = []
  for (var i = 0; i < res.count; i++) {
    var obs = res.objectAtIndex(i)
    try {
      var c = obs.topCandidates(1)
      if (c.count > 0) obsArr.push({y: obs.boundingBox.origin.y, s: c.objectAtIndex(0).string.js})
    } catch (e2) {}
  }
  // Vision origin is bottom-left: higher y = closer to top of image
  obsArr.sort(function (a, b) { return b.y - a.y })
  return obsArr.map(function (o) { return o.s }).join(String.fromCharCode(10))
}
"""

JXA_QR = """
ObjC.import('Vision')
ObjC.import('Foundation')
function run(argv) {
  var url = $.NSURL.fileURLWithPath(argv[0])
  var handler = $.VNImageRequestHandler.alloc.initWithURLOptions(url, $.NSDictionary.dictionary)
  var req = $.VNDetectBarcodesRequest.alloc.init
  var err = Ref()
  handler.performRequestsError($.NSArray.arrayWithObject(req), err)
  if (err[0] && !err[0].isNil()) return JSON.stringify({error: 'barcode request failed'})
  var res = req.results
  if (!res) return JSON.stringify({codes: []})
  var out = []
  for (var i = 0; i < res.count; i++) {
    var obs = res.objectAtIndex(i)
    var item = {payload: '', symbology: ''}
    try { item.payload = obs.payloadStringValue.js } catch (e) {}
    try {
      var sym = obs.symbology
      item.symbology = sym && sym.js !== undefined ? sym.js : String(sym)
    } catch (e2) {}
    out.push(item)
  }
  return JSON.stringify({codes: out})
}
"""

CLIP_IMAGE_APPLESCRIPT = '''
use framework "AppKit"
use scripting additions
set pb to current application's NSPasteboard's generalPasteboard()
set d to (pb's dataForType:(current application's NSPasteboardTypePNG))
if d is missing value then return ""
set b64 to d's base64EncodedStringWithOptions:(0)
return (b64 as text)
'''


def _helper_dir():
    """Private per-user cache for generated JXA/AppleScript helpers."""
    path = os.path.join(tempfile.gettempdir(), "scamcheck-%d" % os.getuid())
    try:
        os.makedirs(path, mode=0o700, exist_ok=True)
        os.chmod(path, 0o700)
    except OSError:
        return None
    return path


def _write_jxa(name, source):
    """Cache a JXA script in a private dir and return its path."""
    folder = _helper_dir()
    if not folder:
        return None
    path = os.path.join(folder, name)
    try:
        existing = None
        if os.path.isfile(path) and not os.path.islink(path):
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                existing = fh.read()
        if existing == source:
            return path
        fd, tmp = tempfile.mkstemp(dir=folder, prefix=".jxa-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(source)
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
    except OSError:
        return None
    return path


def _jxa_vision_ocr(image_path):
    """macOS Apple Vision OCR."""
    script = _write_jxa("scamcheck-vision.js", JXA_OCR)
    if not script:
        return None
    try:
        proc = subprocess.run(
            ["osascript", "-l", "JavaScript", script, image_path],
            capture_output=True,
            timeout=60,
        )
        if proc.returncode != 0:
            return None
        text = proc.stdout.decode("utf-8", "replace").strip()
        return text if text else None
    except (OSError, subprocess.TimeoutExpired):
        return None


# ---------------------------------------------------------------------------
# Tier 2: tesseract
# ---------------------------------------------------------------------------


_TESS_LANGS_CACHE = None


def _tesseract_langs():
    """Cached `tesseract --list-langs` (None when tesseract is missing)."""
    global _TESS_LANGS_CACHE
    if _TESS_LANGS_CACHE is None:
        if not shutil.which("tesseract"):
            _TESS_LANGS_CACHE = ()
            return _TESS_LANGS_CACHE
        try:
            proc = subprocess.run(
                ["tesseract", "--list-langs"], capture_output=True, timeout=15,
            )
            if proc.returncode != 0:
                _TESS_LANGS_CACHE = ()
            else:
                _TESS_LANGS_CACHE = tuple(
                    l.strip() for l in proc.stdout.decode("utf-8", "replace").splitlines()[1:]
                    if l.strip()
                )
        except (OSError, subprocess.TimeoutExpired):
            _TESS_LANGS_CACHE = ()
    return _TESS_LANGS_CACHE


def _tesseract_ocr(image_path):
    langs = _tesseract_langs()
    if not langs:
        return None
    # Default chain: English plus every extra Indian/third language the
    # user installed (tesseract-lang / tesseract-hin), e.g. `hin`, `mr`.
    have = {"eng"} & set(langs) or {langs[0]}
    have |= set(langs) & {"hin", "mr", "ben", "tam", "tel", "urd", "ara"}
    cmd = ["tesseract", image_path, "stdout", "--psm", "6",
           "-l", "+".join(sorted(have))]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=60)
        if proc.returncode != 0:
            # Language pack broken? Retry with the first available.
            proc = subprocess.run(
                ["tesseract", image_path, "stdout", "--psm", "6",
                 "-l", langs[0]],
                capture_output=True, timeout=60,
            )
            if proc.returncode != 0:
                return None
        text = proc.stdout.decode("utf-8", "replace").strip()
        return text if text else None
    except (OSError, subprocess.TimeoutExpired):
        return None


# ---------------------------------------------------------------------------
# Tier 3: AI vision (OpenAI-compatible), only when local engines are missing.
# ---------------------------------------------------------------------------


def _ai_vision_ocr(image_path):
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        return None
    try:
        with open(image_path, "rb") as fh:
            b64 = base64.b64encode(fh.read()).decode()
    except OSError:
        return None
    base = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    model = os.environ.get("SCAMCHECK_VISION_MODEL", "gpt-4o-mini")
    try:
        import urllib.request

        req = urllib.request.Request(
            base + "/chat/completions",
            data=json.dumps({
                "model": model,
                "messages": [{
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Transcribe ALL text exactly as it appears in this image, preserving line breaks, order and the original language/script (Devanagari stays Devanagari, do not translate). Output only the transcription."},
                        {"type": "image_url", "image_url": {"url": "data:image/png;base64," + b64}},
                    ],
                }],
                "temperature": 0,
                "max_tokens": 1500,
            }).encode(),
            headers={"Authorization": "Bearer " + api_key, "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode())
        return data["choices"][0]["message"]["content"].strip() or None
    except Exception:
        return None


ENGINES = (
    ("apple-vision", _jxa_vision_ocr),
    ("tesseract", _tesseract_ocr),
    ("ai-vision", _ai_vision_ocr),
)


def ocr_image(image_path):
    """Return (text, engine_name). text is '' if nothing worked."""
    if not os.path.exists(image_path):
        return None, "not_found: " + image_path
    for name, engine in ENGINES:
        try:
            out = engine(image_path)
        except Exception:
            out = None
        if out and out.strip():
            return out, name
    return "", "none"


def detect_qr(image_path):
    """Decode QR/barcodes with Apple Vision.

    Returns {"available": bool, "codes": [{"payload", "symbology"}], "error"}.
    `available` is False when the platform has no usable decoder; an image
    with no codes is a successful empty result. No network access.
    """
    if not image_path or not os.path.exists(image_path):
        return {"available": False, "codes": [],
                "error": "not_found: " + str(image_path)}
    script = _write_jxa("scamcheck-vision-qr.js", JXA_QR)
    if not script:
        return {"available": False, "codes": [], "error": "cannot write helper"}
    try:
        proc = subprocess.run(
            ["osascript", "-l", "JavaScript", script, image_path],
            capture_output=True, timeout=45,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"available": False, "codes": [], "error": str(exc)}
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", "replace").strip() or "osascript failed"
        return {"available": False, "codes": [], "error": detail[:200]}
    raw = proc.stdout.decode("utf-8", "replace").strip()
    try:
        data = json.loads(raw)
    except ValueError:
        return {"available": False, "codes": [], "error": "could not parse decoder output"}
    if data.get("error"):
        return {"available": False, "codes": [], "error": str(data["error"])}
    codes, seen = [], set()
    for item in data.get("codes") or []:
        payload = (item.get("payload") or "").strip()
        if not payload or payload in seen:
            continue
        seen.add(payload)
        sym = (item.get("symbology") or "").replace("VNBarcodeSymbology", "")
        codes.append({"payload": payload, "symbology": sym or "barcode"})
    return {"available": True, "codes": codes, "error": None}


def qr_text(codes):
    """Render decoded payloads as analyzer-friendly text lines."""
    return "\n".join("QR code: " + c["payload"] for c in codes or [] if c.get("payload"))


# ---------------------------------------------------------------------------
# Clipboard helpers (images AND text) for the --watch mode
# ---------------------------------------------------------------------------


def get_clipboard_image():
    """Return PNG bytes from the clipboard, or None.

    Uses AppleScript-ObjC (JXA refuses to bridge NSPasteboard's
    +generalPasteboard class method on this macOS build).
    """
    try:
        proc = subprocess.run(
            ["osascript"],
            input=CLIP_IMAGE_APPLESCRIPT.encode(),
            capture_output=True, timeout=30,
        )
        b64 = proc.stdout.decode("ascii", "ignore").strip()
        if proc.returncode != 0 or not b64:
            return None
        return base64.b64decode(b64)
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None


def get_clipboard_text():
    try:
        proc = subprocess.run(["pbpaste"], capture_output=True, timeout=10)
        return proc.stdout.decode("utf-8", "replace").strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def clipboard_to_tempfile(png_bytes):
    fd, path = tempfile.mkstemp(suffix=".png", prefix="scamcheck-clip-")
    with os.fdopen(fd, "wb") as fh:
        fh.write(png_bytes)
    return path
