#!/usr/bin/env bash
# Disable PHP session upload progress in known global PHP ini files.
# Default mode is dry-run. Use --apply to write changes or --check to verify only.
set -Eeuo pipefail
shopt -s nullglob

MODE="dry-run"
case "${1:-}" in
  "") ;;
  --apply) MODE="apply" ;;
  --dry-run) MODE="dry-run" ;;
  --check) MODE="check" ;;
  -h|--help)
    cat <<'USAGE'
Usage: bash disable-session-upload-progress.sh [--dry-run|--apply|--check]

  --dry-run  List detected panels, PHP CLI binaries and candidate INI files (default).
  --apply    Back up and modify discovered global INI files, then verify file and PHP CLI settings.
  --check    Do not modify files; verify that each discovered INI file explicitly sets
             session.upload_progress.enabled = Off and each discovered PHP CLI reports Off.

Run as root. Changed files get a timestamped .bak.session-upload-progress-* backup.
The script does not restart/reload PHP-FPM, Apache, LiteSpeed or other services.
NOTE: CLI verification does not prove the effective setting for PHP-FPM/LiteSpeed web requests.
USAGE
    exit 0
    ;;
  *) echo "Unknown option: $1 (use --help)" >&2; exit 2 ;;
esac

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "ERROR: Run this script as root." >&2
  exit 1
fi

panels=()
[[ -d /usr/local/cpanel && ( -e /usr/local/cpanel/cpanel || -e /usr/local/cpanel/version ) ]] && panels+=("cPanel/WHM")
[[ -d /usr/local/directadmin && ( -e /usr/local/directadmin/conf/directadmin.conf || -x /usr/local/directadmin/directadmin ) ]] && panels+=("DirectAdmin")
[[ -e /usr/local/psa/version || -x /usr/bin/plesk || -x /usr/sbin/plesk ]] && panels+=("Plesk")
if ((${#panels[@]} == 0)); then panels+=("Bilinmeyen/genel Linux PHP kurulumu"); fi

printf 'Panel tespiti: %s\n' "$(IFS=', '; echo "${panels[*]}")"
printf 'Mod: %s\n\n' "$MODE"

declare -A seen_bins=()
declare -A seen_ini=()
PHP_BINS=()
INI_FILES=()

# Use colors on interactive terminals, while keeping redirected output clean.
if [[ -t 1 ]]; then
  GREEN=$'\033[0;32m'
  RED=$'\033[0;31m'
  YELLOW=$'\033[0;33m'
  RESET=$'\033[0m'
else
  GREEN=''
  RED=''
  YELLOW=''
  RESET=''
fi

print_ok()   { printf '%b[OK]%b %s\n' "$GREEN" "$RESET" "$*"; }
print_fail() { printf '%b[FAIL]%b %s\n' "$RED" "$RESET" "$*"; }
print_warn() { printf '%b[UYARI]%b %s\n' "$YELLOW" "$RESET" "$*"; }

is_off_value() {
  local value
  value="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
  [[ "$value" == 'off' || "$value" == '0' || "$value" == 'false' || "$value" == 'no' ]]
}

# Return success only if this executable is a real PHP CLI binary.
# Some systems expose php-cgi as /usr/bin/php; running `-i` there may print
# the php-cgi usage help instead of PHP configuration information.
is_php_cli() {
  local bin="$1" sapi rc
  local tempout
  tempout="$(mktemp)" || return 1
  if "$bin" -r 'echo PHP_SAPI;' >"$tempout" 2>&1; then
    rc=0
  else
    rc=$?
  fi
  sapi="$(cat "$tempout" 2>/dev/null || true)"
  rm -f -- "$tempout"
  [[ $rc -eq 0 && "$sapi" == 'cli' ]]
}

# Verify the setting in the actual contents of each discovered INI file.
verify_ini_file() {
  local ini="$1" line value count
  local -a active_lines=()
  mapfile -t active_lines < <(grep -E '^[[:space:]]*session[.]upload_progress[.]enabled[[:space:]]*=' "$ini" || true)
  count=${#active_lines[@]}

  if (( count != 1 )); then
    print_fail "$ini: etkin ayar satırı sayısı $count (beklenen: 1)."
    return 1
  fi

  line="${active_lines[0]}"
  value="$(printf '%s\n' "$line" | sed -E 's/^[^=]*=[[:space:]]*//; s/[;#].*$//; s/^[[:space:]]*//; s/[[:space:]]*$//')"
  if is_off_value "$value"; then
    print_ok "$ini: session.upload_progress.enabled = $value (dosya doğrulandı)"
    return 0
  fi

  print_fail "$ini: session.upload_progress.enabled değeri '$value'; Off bekleniyordu."
  return 1
}

# Verify each discovered PHP CLI's effective value using php -i.
verify_php_cli_settings() {
  local bin output line local_value master_value version loaded_ini
  local current_failed=0
  local checked=0

  if ((${#PHP_BINS[@]} == 0)); then
    print_fail 'Doğrulama için kullanılabilir gerçek PHP CLI binary bulunamadı; php -i ile etkin değer doğrulanamadı.'
    return 1
  fi

  printf '\nPHP CLI etkin ayar doğrulaması (php -i):\n'
  for bin in "${PHP_BINS[@]}"; do
    # Extra validation avoids accidentally printing php-cgi Usage text as a version.
    if ! is_php_cli "$bin"; then
      print_warn "$bin: PHP CLI olarak doğrulanamadığı için atlanıyor."
      continue
    fi

    version="$("$bin" -r 'echo PHP_VERSION;' 2>/dev/null || true)"
    if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]]; then
      print_fail "$bin: PHP sürümü güvenilir biçimde alınamadı; binary atlanıyor."
      current_failed=1
      continue
    fi
    loaded_ini="$("$bin" -r 'echo php_ini_loaded_file() ?: "(php.ini yüklenmemiş)";' 2>/dev/null || true)"
    output="$("$bin" -i 2>&1)" || {
      print_fail "$bin (PHP $version): php -i komutu başarısız oldu."
      current_failed=1
      continue
    }
    line="$(printf '%s\n' "$output" | grep -m1 -E '^[[:space:]]*session[.]upload_progress[.]enabled[[:space:]]*=>' || true)"

    if [[ -z "$line" ]]; then
      print_fail "$bin (PHP $version): php -i çıktısında session.upload_progress.enabled bulunamadı. php.ini=${loaded_ini:-belirlenemedi}"
      current_failed=1
      continue
    fi

    # PHP -i usually reports: directive => Local Value => Master Value.
    local_value="${line#*=>}"
    local_value="${local_value%%=>*}"
    local_value="$(printf '%s' "$local_value" | sed -E 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    master_value="${line##*=>}"
    master_value="$(printf '%s' "$master_value" | sed -E 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    checked=$((checked+1))

    if is_off_value "$local_value" && is_off_value "$master_value"; then
      print_ok "$bin (PHP $version): session.upload_progress.enabled => $local_value => $master_value"
      printf '     php.ini: %s\n' "${loaded_ini:-belirlenemedi}"
    else
      print_fail "$bin (PHP $version): etkin değer '$local_value', master değer '$master_value' (Off => Off bekleniyordu)."
      printf '      php.ini: %s\n' "${loaded_ini:-belirlenemedi}"
      current_failed=1
    fi
  done

  if (( checked == 0 )); then
    print_fail 'Hiçbir PHP CLI binary etkin ayar doğrulamasına ulaşamadı.'
    return 1
  fi
  return "$current_failed"
}

add_bin() {
  local p="$1"
  [[ -x "$p" && ! -d "$p" ]] || return 0
  [[ -n "${seen_bins[$p]+x}" ]] && return 0
  seen_bins[$p]=1

  if ! is_php_cli "$p"; then
    if [[ "$p" == '/usr/bin/php' || "$p" == '/usr/local/bin/php' ]]; then
      print_warn "$p PHP CLI değil veya -r desteklemiyor (muhtemelen php-cgi); php -i doğrulamasına alınmadı."
    fi
    return 0
  fi
  PHP_BINS+=("$p")
}

add_ini() {
  local p="$1" real
  [[ -f "$p" && -r "$p" ]] || return 0
  real="$(readlink -f -- "$p" 2>/dev/null || printf '%s' "$p")"
  [[ -f "$real" && -r "$real" ]] || return 0
  [[ -n "${seen_ini[$real]+x}" ]] && return 0
  seen_ini[$real]=1
  INI_FILES+=("$real")
}

# PHP CLI binaries commonly used by cPanel/EasyApache, CloudLinux alt-php,
# DirectAdmin CustomBuild, Plesk, and OS packages.
for bin in \
  /usr/local/bin/ea-php[0-9][0-9] \
  /opt/cpanel/ea-php*/root/usr/bin/php \
  /opt/alt/php*/usr/bin/php \
  /usr/local/php*/bin/php \
  /opt/plesk/php/*/bin/php \
  /usr/bin/php /usr/bin/php[0-9].[0-9] \
  /usr/local/bin/php; do
  add_bin "$bin"
done

printf 'Bulunan PHP CLI sürümleri:\n'
if ((${#PHP_BINS[@]} == 0)); then
  echo '  PHP CLI binary bulunamadı; bilinen yapılandırma yolları taranacak.'
else
  for bin in "${PHP_BINS[@]}"; do
    version="$("$bin" -r 'echo PHP_VERSION;' 2>/dev/null || printf 'bilinmiyor')"
    ini="$("$bin" -r 'echo php_ini_loaded_file() ?: "(php.ini yüklenmemiş)";' 2>/dev/null || printf 'belirlenemedi')"
    printf '  PHP %-10s binary=%s\n    ini=%s\n' "${version:-bilinmiyor}" "$bin" "${ini:-belirlenemedi}"
    [[ -n "$ini" && "$ini" != '(php.ini yüklenmemiş)' && "$ini" != 'belirlenemedi' ]] && add_ini "$ini"

    # Include scanned .ini files only if they explicitly set this directive.
    scanned="$("$bin" -r 'echo php_ini_scanned_files() ?: "";' 2>/dev/null || true)"
    if [[ -n "$scanned" ]]; then
      while IFS= read -r scanfile; do
        [[ -n "$scanfile" ]] || continue
        if [[ -f "$scanfile" ]] && grep -Eq '^[[:space:]]*session[.]upload_progress[.]enabled[[:space:]]*=' "$scanfile"; then
          add_ini "$scanfile"
        fi
      done < <(printf '%s' "$scanned" | tr ';,' '\n' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
    fi
  done
fi

# Known main php.ini paths for installs that do not expose a matching CLI binary.
for ini in \
  /opt/cpanel/ea-php*/root/etc/php.ini \
  /opt/alt/php*/etc/php.ini \
  /usr/local/php*/lib/php.ini \
  /opt/plesk/php/*/etc/php.ini \
  /etc/php.ini \
  /etc/php/*/fpm/php.ini \
  /etc/php/*/apache2/php.ini \
  /etc/php/*/cli/php.ini \
  /etc/php/*/cgi/php.ini \
  /var/www/vhosts/system/*/etc/php.ini \
  /usr/local/directadmin/data/users/*/php/*.ini; do
  add_ini "$ini"
done

printf '\nBulunan PHP yapılandırma dosyaları (%d):\n' "${#INI_FILES[@]}"
if ((${#INI_FILES[@]} == 0)); then
  print_fail 'php.ini bulunamadı. Hiçbir dosya değiştirilmedi.'
  exit 1
fi
for ini in "${INI_FILES[@]}"; do
  if grep -Eq '^[[:space:]]*session[.]upload_progress[.]enabled[[:space:]]*=[[:space:]]*(Off|off|0|false|no)[[:space:]]*([;#].*)?$' "$ini"; then
    state='zaten Off/0'
  elif grep -Eq '^[[:space:]]*session[.]upload_progress[.]enabled[[:space:]]*=' "$ini"; then
    state='aktif değer var; Off yapılacak'
  else
    state='ayar yok; eklenecek'
  fi
  printf '  [%s] %s\n' "$state" "$ini"
done

if [[ "$MODE" == 'dry-run' ]]; then
  cat <<'NOTE'

DRY-RUN: Hiçbir dosya değiştirilmedi.
Uygulamak için:
  bash disable-session-upload-progress.sh --apply
Yalnızca doğrulama yapmak için:
  bash disable-session-upload-progress.sh --check
NOTE
  exit 0
fi

if [[ "$MODE" == 'check' ]]; then
  printf '\nCHECK: Hiçbir dosya değiştirilmeyecek; mevcut durum doğrulanıyor.\n'
  verification_failed=0
  for ini in "${INI_FILES[@]}"; do
    verify_ini_file "$ini" || verification_failed=1
  done
  verify_php_cli_settings || verification_failed=1
  if (( verification_failed > 0 )); then
    printf '\nCHECK SONUCU: BAŞARISIZ — yukarıdaki [FAIL] satırlarını inceleyin.\n'
    exit 1
  fi
  printf '\nCHECK SONUCU: BAŞARILI — bulunan INI dosyaları ve PHP CLI ayarları Off olarak doğrulandı.\n'
  exit 0
fi

stamp="$(date +%Y%m%d-%H%M%S)"
changed=0
failed=0
for ini in "${INI_FILES[@]}"; do
  backup="${ini}.bak.session-upload-progress-${stamp}"
  tmp="$(mktemp "${ini}.tmp.XXXXXX")" || { echo "HATA: Geçici dosya oluşturulamadı: $ini" >&2; failed=$((failed+1)); continue; }

  if ! cp -a -- "$ini" "$backup"; then
    echo "HATA: Yedek alınamadı: $ini" >&2
    rm -f -- "$tmp"
    failed=$((failed+1))
    continue
  fi

  # Put one canonical boolean before any INI section header and remove all active duplicates.
  if ! awk '
    BEGIN { print "session.upload_progress.enabled = Off"; print "" }
    /^[[:space:]]*session[.]upload_progress[.]enabled[[:space:]]*=/ { next }
    { print }
  ' "$ini" > "$tmp"; then
    echo "HATA: Dosya işlenemedi: $ini (yedek: $backup)" >&2
    rm -f -- "$tmp"
    failed=$((failed+1))
    continue
  fi

  # Preserve permissions/ownership and supported ACL/xattr metadata where possible.
  cp --attributes-only --preserve=all -- "$ini" "$tmp" 2>/dev/null || {
    chown --reference="$ini" "$tmp" 2>/dev/null || true
    chmod --reference="$ini" "$tmp" 2>/dev/null || true
  }

  if mv -f -- "$tmp" "$ini"; then
    command -v restorecon >/dev/null 2>&1 && restorecon -F "$ini" >/dev/null 2>&1 || true
    printf 'GÜNCELLENDİ: %s\nYedek: %s\n' "$ini" "$backup"
    changed=$((changed+1))
  else
    echo "HATA: Dosya değiştirilemedi: $ini (yedek: $backup)" >&2
    rm -f -- "$tmp"
    failed=$((failed+1))
  fi
done

printf '\nDosya içeriği doğrulaması:\n'
verification_failed=0
for ini in "${INI_FILES[@]}"; do
  verify_ini_file "$ini" || verification_failed=1
done

verify_php_cli_settings || verification_failed=1

printf '\nTamamlandı. Güncellenen dosya: %d; dosya işlemi hatası: %d; doğrulama hatası: %d\n' \
  "$changed" "$failed" "$verification_failed"
cat <<'NOTE'

ÖNEMLİ:
- Script servisleri yeniden başlatmaz/reload etmez.
- PHP-FPM kullanan sistemlerde değişikliğin web isteklerine uygulanması için ilgili PHP-FPM servislerinin kontrollü reload/restart edilmesi gerekebilir.
- Bu ayar PHP_INI_PERDIR kapsamındadır. .user.ini, vhost veya PHP-FPM pool ayarları değeri tekrar açabilir; web tarafında ayrıca doğrulayın.
- PHP -i doğrulaması yalnızca bulunan gerçek PHP CLI binary'lerini kontrol eder; PHP-FPM/LiteSpeed web handler'ının etkin yapılandırmasını kesin olarak doğrulamaz.
- Bu, CVE-2026-109618/109619 için geçici bir azaltımdır; PHP/vendor güvenlik yamalarının yerine geçmez.
NOTE

if (( failed > 0 || verification_failed > 0 )); then
  exit 1
fi
exit 0
