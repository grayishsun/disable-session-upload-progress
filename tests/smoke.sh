#!/usr/bin/env bash
# Minimal smoke test for disable-session-upload-progress.sh.
# Usage: bash tests/smoke.sh
# Needs only bash; no root, no PHP, no network. Uses temp fixtures.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/disable-session-upload-progress.sh"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); printf 'PASS: %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf 'FAIL: %s\n' "$1"; }
count_matches() { grep -c -E "$1" "$2" 2>/dev/null || true; }

T="$(mktemp -d "${TMPDIR:-/tmp}/php-hardening-test.XXXXXX")"
trap 'rm -rf "$T"' EXIT
export HARDENING_ALLOW_NON_ROOT=1

# --- fixtures ---
printf '%s\n' '; [PHP] basligi yok' 'expose_php = On' > "$T/no-php.ini"
printf '%s\n' '[PHP]' 'session.upload_progress.enabled = On' 'post_max_size = 64M' > "$T/with-php.ini"
printf '%s\n' \
  '; disable-session-upload-progress.sh v2.1.0 -- profil: standard -- 2026-10-21' \
  '; Bu blok betik tarafindan yonetilir. Onceki icerik su dosyaya yedeklendi:' \
  ';   /tmp/x/php.ini.bak.session-upload-progress-20261021-230000' \
  '; Tekrar --apply calistirmak guvenlidir (idempotent).' \
  'session.upload_progress.enabled = Off' \
  '' \
  '[PHP]' \
  'engine = On' > "$T/legacy.ini"
printf '%s\n' '[www]' 'pm.max_requests = 500' \
  'php_admin_value[session.upload_progress.enabled] = On' > "$T/pool.conf"
cp "$T/no-php.ini" "$T/no-php.orig"
cp "$T/with-php.ini" "$T/with-php.orig"
cp "$T/legacy.ini" "$T/legacy.orig"
cp "$T/pool.conf" "$T/pool.orig"

INI="--ini $T/no-php.ini --ini $T/with-php.ini --ini $T/legacy.ini"
POOL="--pool-conf $T/pool.conf"

# 1. syntax
if bash -n "$SCRIPT"; then pass "bash -n temiz"; else fail "bash -n hatalı"; fi

# 2. dry-run changes nothing
cp "$T/with-php.ini" "$T/with-php.predry"
if bash "$SCRIPT" $INI --profile minimal --cve-mitigate --dry-run > "$T/dry.log" 2>&1; then
  pass "dry-run çıkış kodu 0"
else
  fail "dry-run çıkış kodu 0 değil"
fi
if cmp -s "$T/with-php.predry" "$T/with-php.ini"; then
  pass "dry-run dosyayı değiştirmedi"
else
  fail "dry-run dosyayı değiştirdi"
fi

# 3. apply (CVE katmanı + havuz dahil)
bash "$SCRIPT" $INI $POOL --profile minimal --cve-mitigate --enforce-pools --apply --yes > "$T/apply.log" 2>&1
if grep -q 'unbound variable' "$T/apply.log"; then
  fail "apply logunda 'unbound variable' var"
else
  pass "apply 'unbound variable' hatasız tamamlandı"
fi
if [ "$(head -n1 "$T/no-php.ini")" = "[PHP]" ]; then
  pass "[PHP] başlığı olmayan dosyaya başlık eklendi"
else
  fail "[PHP] başlığı eklenemedi"
fi
if [ "$(count_matches 'BEGIN php-ini-hardening' "$T/no-php.ini")" = "1" ] \
  && [ "$(count_matches 'BEGIN php-ini-hardening' "$T/with-php.ini")" = "1" ] \
  && [ "$(count_matches 'BEGIN php-ini-hardening' "$T/legacy.ini")" = "1" ]; then
  pass "her ini dosyasında tek yönetilen blok var"
else
  fail "yönetilen blok sayısı hatalı"
fi
if [ "$(sed -n '2p' "$T/with-php.ini" | cut -c1-25)" = "; BEGIN php-ini-hardening" ]; then
  pass "blok [PHP] başlığının hemen altında"
else
  fail "blok [PHP] altında değil"
fi
if grep -q 'v2.1.0 -- profil' "$T/legacy.ini"; then
  fail "eski sürüm yorum artığı temizlenemedi"
else
  pass "eski sürüm yorum artığı temizlendi"
fi
if [ "$(count_matches '^[[:space:]]*post_max_size[[:space:]]*=[[:space:]]*32M' "$T/with-php.ini")" = "1" ]; then
  pass "CVE katmanı uygulandı (post_max_size 64M -> 32M)"
else
  fail "CVE katmanı uygulanamadı"
fi
if [ "$(count_matches 'BEGIN php-cve-hardening' "$T/pool.conf")" = "1" ] \
  && grep -q 'php_admin_value\[session.upload_progress.enabled\] = Off' "$T/pool.conf"; then
  pass "havuz bloğu yazıldı"
else
  fail "havuz bloğu yazılamadı"
fi

# 4. idempotency: ikinci apply çoğaltmamalı
bash "$SCRIPT" $INI $POOL --profile minimal --cve-mitigate --enforce-pools --apply --yes > /dev/null 2>&1
if [ "$(count_matches '^[[:space:]]*\[PHP\]' "$T/no-php.ini")" = "1" ] \
  && [ "$(count_matches 'BEGIN php-ini-hardening' "$T/no-php.ini")" = "1" ] \
  && [ "$(count_matches 'BEGIN php-cve-hardening' "$T/pool.conf")" = "1" ]; then
  pass "ikinci apply idempotent (tekrar yok)"
else
  fail "ikinci apply çoğalttı"
fi

# 5. check: dosya/havuz doğrulaması OK olmalı (PHP CLI yoksa yalnızca o adım FAIL verir)
bash "$SCRIPT" $INI $POOL --profile minimal --cve-mitigate --enforce-pools --check > "$T/check.log" 2>&1
if grep -q 'dosya doğrulandı' "$T/check.log" \
  && ! grep -E '^\[FAIL\].*\.ini:' "$T/check.log" \
  && ! grep -E '^\[FAIL\].*\.conf:' "$T/check.log"; then
  pass "check dosya/havuz doğrulaması temiz"
else
  fail "check dosya/havuz doğrulaması hatalı"
fi

# 6. restore: orijinallerle birebir
bash "$SCRIPT" $INI $POOL --enforce-pools --restore --yes > /dev/null 2>&1
restored_ok=1
for f in no-php with-php legacy; do
  cmp -s "$T/$f.orig" "$T/$f.ini" || restored_ok=0
done
cmp -s "$T/pool.orig" "$T/pool.conf" || restored_ok=0
if [ "$restored_ok" = "1" ]; then
  pass "restore orijinallerle birebir"
else
  fail "restore farklı içerik üretti"
fi

printf '\nSonuç: %d geçti, %d kaldı\n' "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then exit 1; fi
exit 0
