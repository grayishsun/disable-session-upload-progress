#!/usr/bin/env bash
# Disable PHP session upload progress in known global PHP ini files.
# Default mode is dry-run. Use --apply to write changes.
set -Eeuo pipefail
shopt -s nullglob

MODE="dry-run"
case "${1:-}" in
  "") ;;
  --apply) MODE="apply" ;;
  --dry-run) MODE="dry-run" ;;
  -h|--help)
    cat <<'USAGE'
Usage: bash disable-session-upload-progress.sh [--dry-run|--apply]

  --dry-run  List detected panels, PHP binaries and candidate ini files (default).
  --apply    Back up and modify discovered global php.ini files.

Run as root. Each changed file gets a timestamped .bak.session-upload-progress-* backup.
The script does not restart PHP-FPM, Apache, LiteSpeed or other services.
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

add_bin() {
  local p="$1"
  [[ -x "$p" && ! -d "$p" ]] || return 0
  [[ -n "${seen_bins[$p]+x}" ]] && return 0
  seen_bins[$p]=1
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
    version="$("$bin" -r 'echo PHP_VERSION;' 2>/dev/null || true)"
    ini="$("$bin" -r 'echo php_ini_loaded_file() ?: "(php.ini yüklenmemiş)";' 2>/dev/null || true)"
    printf '  PHP %-10s binary=%s\n    ini=%s\n' "${version:-bilinmiyor}" "$bin" "${ini:-belirlenemedi}"
    [[ -n "$ini" && "$ini" != '(php.ini yüklenmemiş)' ]] && add_ini "$ini"

    # If a scanned .ini file explicitly sets this directive, include it too,
    # because it can override the value in the main php.ini.
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
  echo '  php.ini bulunamadı. Hiçbir dosya değiştirilmedi.'
  exit 0
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
NOTE
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

  # Put one canonical boolean before any INI section header and remove all
  # active duplicates from the file, avoiding ambiguous duplicate directives.
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

  # Preserve basic permissions/ownership and, where supported, ACL/xattr metadata.
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

printf '\nTamamlandı. Güncellenen dosya: %d; hata: %d\n' "$changed" "$failed"
cat <<'NOTE'

ÖNEMLİ:
- Script servisleri yeniden başlatmaz/reload etmez.
- PHP-FPM kullanan sistemlerde değişikliğin web isteklerine uygulanması için ilgili PHP-FPM servislerinin kontrollü reload/restart edilmesi gerekebilir.
- Bu ayar PHP_INI_PERDIR kapsamındadır. .user.ini, vhost veya PHP-FPM pool ayarları değeri tekrar açabilir; web tarafında ayrıca doğrulayın.
- Bu, CVE-2026-109618/109619 için geçici bir azaltımdır; PHP/vendor güvenlik yamalarının yerine geçmez.
NOTE
