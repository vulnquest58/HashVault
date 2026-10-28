#!/usr/bin/env bash
# HashVault — سكربت تحميل الموارد الرسمي
# الاستخدام: bash scripts/fetch_resources.sh [--skip-wordlists] [--skip-tools]

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="$PROJECT_ROOT/data"
TOOLS_DIR="$PROJECT_ROOT/tools"
TMP_DIR="$(mktemp -d)"

SKIP_WORDLISTS=false
SKIP_TOOLS=false
for arg in "$@"; do
    case "$arg" in
        --skip-wordlists) SKIP_WORDLISTS=true ;;
        --skip-tools) SKIP_TOOLS=true ;;
    esac
done

trap 'rm -rf "$TMP_DIR"' EXIT

log()  { echo -e "\033[1;34m[HashVault]\033[0m $*"; }
warn() { echo -e "\033[1;33m[تحذير]\033[0m $*"; }
err()  { echo -e "\033[1;31m[خطأ]\033[0m $*" >&2; }

write_manifest_entry() {
    # $1=manifest_path $2=name $3=source_url $4=commit_or_version $5=fetched_at
    local manifest="$1"
    python3 - "$manifest" "$2" "$3" "$4" "$5" <<'PYEOF'
import json, sys, pathlib
manifest_path, name, url, ver, ts = sys.argv[1:6]
p = pathlib.Path(manifest_path)
data = json.loads(p.read_text()) if p.exists() else {"entries": []}
entries = [e for e in data.get("entries", []) if e.get("name") != name]
entries.append({"name": name, "source_url": url, "version": ver, "fetched_at": ts})
data["entries"] = entries
p.write_text(json.dumps(data, indent=2, ensure_ascii=False))
PYEOF
}

# ── 1. تحقق من الأدوات الأساسية اللازمة للتحميل نفسه ──────────────────────
for cmd in git curl python3; do
    command -v "$cmd" >/dev/null 2>&1 || { err "الأداة $cmd غير مثبتة — لا يمكن المتابعة."; exit 1; }
done

mkdir -p "$DATA_DIR/rules/hashcat-rules" "$DATA_DIR/wordlists/seclists" "$TOOLS_DIR/hashcat" "$TOOLS_DIR/john"

# ── 2. قواعد Hashcat الرسمية ────────────────────────────────────────────
log "تحميل قواعد Hashcat من المستودع الرسمي..."
git clone --depth 1 https://github.com/hashcat/hashcat.git "$TMP_DIR/hashcat" 2>&1 | tail -5

if [ -d "$TMP_DIR/hashcat/rules" ]; then
    cp -v "$TMP_DIR/hashcat/rules/"*.rule "$DATA_DIR/rules/hashcat-rules/" 2>/dev/null || true
    COMMIT_HASH=$(git -C "$TMP_DIR/hashcat" rev-parse --short HEAD)
    write_manifest_entry "$DATA_DIR/rules/manifest.json" "hashcat-rules" \
        "https://github.com/hashcat/hashcat" "$COMMIT_HASH" "$(date -u +%FT%TZ)"
    log "تم نسخ $(ls "$DATA_DIR/rules/hashcat-rules" | wc -l) ملف rule."
else
    err "لم يُعثر على مجلد rules/ داخل المستودع المُنسَّخ."
fi

# ── 3. قوائم الكلمات من SecLists (اختياري، حجم كبير) ────────────────────
if [ "$SKIP_WORDLISTS" = false ]; then
    log "تحميل SecLists (قد يستغرق وقتاً لضخامة الحجم)..."
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$TMP_DIR/seclists" 2>&1 | tail -5

    mkdir -p "$DATA_DIR/wordlists/seclists/Passwords-Common-Credentials"
    mkdir -p "$DATA_DIR/wordlists/seclists/Usernames"

    cp -rv "$TMP_DIR/seclists/Passwords/Common-Credentials/"* \
        "$DATA_DIR/wordlists/seclists/Passwords-Common-Credentials/" 2>/dev/null || true
    cp -rv "$TMP_DIR/seclists/Usernames/"* \
        "$DATA_DIR/wordlists/seclists/Usernames/" 2>/dev/null || true

    # فك ضغط rockyou إن وُجد مضغوطاً
    ROCKYOU_GZ=$(find "$DATA_DIR/wordlists/seclists" -iname "rockyou.txt.gz" | head -1)
    if [ -n "$ROCKYOU_GZ" ]; then
        gunzip -kf "$ROCKYOU_GZ"
        mv "${ROCKYOU_GZ%.gz}" "$DATA_DIR/wordlists/rockyou.txt"
        log "تم فك ضغط rockyou.txt ونقله إلى data/wordlists/"
    else
        warn "لم يُعثر على rockyou.txt.gz ضمن SecLists — تحقق من بنية المستودع الحالية يدوياً."
    fi

    COMMIT_HASH=$(git -C "$TMP_DIR/seclists" rev-parse --short HEAD)
    write_manifest_entry "$DATA_DIR/wordlists/manifest.json" "seclists" \
        "https://github.com/danielmiessler/SecLists" "$COMMIT_HASH" "$(date -u +%FT%TZ)"
else
    log "تخطي تحميل wordlists (--skip-wordlists مفعّل)."
fi

# ── 4. الأدوات الخارجية: تفضيل مدير الحزم أولاً ─────────────────────────
if [ "$SKIP_TOOLS" = false ]; then
    if command -v hashcat >/dev/null 2>&1; then
        log "hashcat مثبت مسبقاً عبر النظام: $(command -v hashcat) — لا حاجة للتحميل اليدوي."
    else
        warn "hashcat غير مثبت. يُفضَّل: sudo apt install hashcat (أو مدير الحزم المناسب لتوزيعتك)."
        warn "سيتم تخطي تحميل binary تلقائياً — التثبيت اليدوي عبر GitHub Releases يتطلب تدخلاً بشرياً"
        warn "للتحقق من التوقيع/checksum يدوياً قبل التشغيل، لأسباب أمنية."
    fi

    if command -v john >/dev/null 2>&1; then
        log "john مثبت مسبقاً عبر النظام: $(command -v john)"
    else
        warn "john غير مثبت. يُفضَّل: sudo apt install john (نسخة jumbo إن توفرت في مستودعات توزيعتك)."
    fi
else
    log "تخطي فحص/تحميل الأدوات (--skip-tools مفعّل)."
fi

log "اكتمل التحميل. راجع data/rules/manifest.json و data/wordlists/manifest.json للتفاصيل."
