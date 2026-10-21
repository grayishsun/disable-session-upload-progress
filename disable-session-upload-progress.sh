#!/usr/bin/env bash
#
# disable-session-upload-progress.sh v2.1 — PHP CVE azaltımı için php.ini sertleştirme betiği
#
# Ne yapar?
#   - Tüm global php.ini dosyalarında "session.upload_progress.enabled = Off" uygular.
#     (CVE-2026-109619'un doğrulanan session yolu + LFI zincirlerine karşı azaltım.)
#   - Seçilen profile göre ek sertleştirme uygular: expose_php, allow_url_include,
#     session.upload_progress.cleanup, display_errors/log_errors ve disable_functions.
#   - --cve-mitigate ile CVE-2026-109618/109619 geçici düzeltmesini katman olarak
#     ekler: post_max_size/upload_max_filesize sıkılaştırma, girdi limitleri ve
#     PHP 8.5+ için fatal_error_backtraces=0 (sürüme duyarlı, PHP 5/7/8 uyumlu).
#   - --enforce-pools ile PHP-FPM havuzlarına php_admin_value zorlaması yazar.
#   - cPanel/WHM (EA4), CloudLinux alt-php, DirectAdmin (CustomBuild), Plesk ve
#     genel Linux (deb/rpm) PHP kurulumlarını otomatik tespit eder.
#
# Varsayılan mod dry-run'dur; hiçbir dosya değiştirilmez.
# Değişiklik için --apply, doğrulama için --check, geri alma için --restore kullanın.
# Betik varsayılan olarak servisleri yeniden başlatmaz/reload etmez
# (--reload/--restart hariç).
#
# Gereksinimler: bash 4+, root (yalnızca --apply/--restore/--reload/--restart için).
# Bu betik geçici azaltımdır; yamalı PHP sürümüne güncellemek tek tam çözümdür.
#
set -Eeuo pipefail
shopt -s nullglob

VERSION="2.1.0"
SCRIPT_NAME="$(basename "${BASH_SOURCE[0]:-$0}")"
BACKUP_SUFFIX="bak.session-upload-progress"
POOL_BLOCK_BEGIN="; BEGIN php-cve-hardening"
POOL_BLOCK_END="; END php-cve-hardening"

MODE="dry-run"
PROFILE="standard"
RELOAD=0
RESTART=0
ASSUME_YES=0
DISABLE_COLOR=0
EXTRA_INIS=()
EXTRA_BINS=()
EXTRA_POOLS=()
CVE_MITIGATE=0
POST_MAX_SIZE="32M"
UPLOAD_MAX_FILESIZE=""
ENFORCE_POOLS=0
POOL_MEMORY_UNLIMITED=0
POOL_MAX_REQUESTS_1=0

usage() {
  cat <<USAGE
Kullanım: bash $SCRIPT_NAME [SEÇENEKLER]

Modlar (varsayılan: --dry-run):
  --dry-run            Panel, PHP sürümleri ve php.ini dosyalarını listeler; değişiklik yapmaz.
  --apply              Yedek alıp bulunan global INI dosyalarını günceller, sonra doğrular.
  --check              Dosya değiştirmez; INI içeriklerini ve PHP CLI etkin değerleri doğrular.
  --restore            Her INI dosyasını en yeni .$BACKUP_SUFFIX-* yedeğinden geri yükler.

Profiller (--profile AD):
  minimal              Yalnızca session.upload_progress.enabled = Off (v1 davranışı).
  standard (varsayılan) minimal + cleanup=On, expose_php=Off, allow_url_include=Off
                       + riskli kabuk/işlem fonksiyonlarını disable_functions ile kapatır.
  strict               standard + display_errors=Off, log_errors=On
                       + genişletilmiş disable_functions listesi.

CVE-2026-109618/109619 geçici düzeltmesi (seçilen profile ek katman):
  --cve-mitigate       post_max_size/upload_max_filesize sıkılaştırma, girdi
                       limitleri (max_input_vars, max_input_nesting_level,
                       max_file_uploads) ve PHP 8.5+ için fatal_error_backtraces=0
                       uygular. Sürüme duyarlıdır; PHP 5/7/8 kapsanır.
  --post-max-size BOYUT
                       Hedef post_max_size (varsayılan: 32M). Yükleme gerekmeyen
                       siteler için 8M önerilir. Örn: 8M, 32M, 1G.
  --upload-max-filesize BOYUT
                       Hedef upload_max_filesize (varsayılan: post_max_size - 1M).
                       post_max_size değerinden küçük olmalıdır.

PHP-FPM havuz zorlaması (yalnızca --apply ile yazar):
  --enforce-pools      Bulunan FPM havuzlarına yönetilen blok yazar:
                       php_admin_value[session.upload_progress.enabled] = Off
  --pool-conf YOL      Keşfe ek FPM havuz dosyası ekler (tekrarlanabilir).
  --pool-memory-unlimited
                       Havuz bloğuna php_admin_value[memory_limit] = -1 ekler.
                       DİKKAT: cgroup/container limiti yoksa tek istek tüm RAM'i
                       tüketebilir. Yama sonrası gerçek limite dönün.
  --pool-max-requests-1
                       Havuz bloğuna pm.max_requests = 1 ekler (her worker tek
                       istek işler). DİKKAT: ciddi performans kaybı olur.

Diğer seçenekler:
  --reload             --apply sonrasında aktif PHP-FPM servislerine reload ve
                       aktif Apache servisine graceful reload yapar.
  --restart            --apply sonrasında aktif PHP-FPM + Apache servislerini
                       yeniden başlatır (--reload yerine geçer; kısa kesinti olur).
  --yes, -y            Onay sorusunu atlar.
  --ini YOL            Ek php.ini dosyası (tekrarlanabilir).
  --php-bin YOL        Ek PHP CLI binary yolu (tekrarlanabilir).
  --no-color           Renkli çıktıyı kapatır (NO_COLOR ortam değişkeni de geçerlidir).
  --version            Sürümü yazdırır.
  -h, --help           Bu yardımı yazdırır.

Örnekler:
  bash $SCRIPT_NAME
  bash $SCRIPT_NAME --apply --profile standard
  bash $SCRIPT_NAME --cve-mitigate --post-max-size 8M
  bash $SCRIPT_NAME --apply --profile standard --cve-mitigate --enforce-pools --restart --yes
  bash $SCRIPT_NAME --check --profile standard --cve-mitigate
  bash $SCRIPT_NAME --restore

Ortam değişkenleri:
  HARDENING_ALLOW_NON_ROOT=1   Root kontrolünü atlar (yalnızca test için).

Notlar:
  - Değişen her dosyanın zaman damgalı .$BACKUP_SUFFIX-* yedeği alınır.
  - PHP -i doğrulaması yalnızca bulunan gerçek PHP CLI binary'lerini kontrol eder;
    PHP-FPM/LiteSpeed web handler'ının etkin değerini kesin olarak kanıtlamaz.
USAGE
}

while (($# > 0)); do
  case "${1:-}" in
    --dry-run) MODE="dry-run"; shift ;;
    --apply) MODE="apply"; shift ;;
    --check) MODE="check"; shift ;;
    --restore) MODE="restore"; shift ;;
    --profile)
      [[ -n "${2:-}" ]] || { echo "HATA: --profile bir değer gerektirir (minimal|standard|strict)." >&2; exit 2; }
      PROFILE="$2"; shift 2 ;;
    --profile=*)
      PROFILE="${1#--profile=}"; shift ;;
    --reload) RELOAD=1; shift ;;
    --restart) RESTART=1; shift ;;
    --cve-mitigate) CVE_MITIGATE=1; shift ;;
    --post-max-size)
      [[ -n "${2:-}" ]] || { echo "HATA: --post-max-size bir boyut değeri gerektirir (örn: 8M)." >&2; exit 2; }
      POST_MAX_SIZE="$2"; shift 2 ;;
    --post-max-size=*)
      POST_MAX_SIZE="${1#--post-max-size=}"; shift ;;
    --upload-max-filesize)
      [[ -n "${2:-}" ]] || { echo "HATA: --upload-max-filesize bir boyut değeri gerektirir (örn: 7M)." >&2; exit 2; }
      UPLOAD_MAX_FILESIZE="$2"; shift 2 ;;
    --upload-max-filesize=*)
      UPLOAD_MAX_FILESIZE="${1#--upload-max-filesize=}"; shift ;;
    --enforce-pools) ENFORCE_POOLS=1; shift ;;
    --pool-conf)
      [[ -n "${2:-}" ]] || { echo "HATA: --pool-conf bir dosya yolu gerektirir." >&2; exit 2; }
      EXTRA_POOLS+=("$2"); shift 2 ;;
    --pool-conf=*)
      EXTRA_POOLS+=("${1#--pool-conf=}"); shift ;;
    --pool-memory-unlimited) POOL_MEMORY_UNLIMITED=1; shift ;;
    --pool-max-requests-1) POOL_MAX_REQUESTS_1=1; shift ;;
    --yes|-y) ASSUME_YES=1; shift ;;
    --no-color) DISABLE_COLOR=1; shift ;;
    --ini)
      [[ -n "${2:-}" ]] || { echo "HATA: --ini bir dosya yolu gerektirir." >&2; exit 2; }
      EXTRA_INIS+=("$2"); shift 2 ;;
    --ini=*)
      EXTRA_INIS+=("${1#--ini=}"); shift ;;
    --php-bin)
      [[ -n "${2:-}" ]] || { echo "HATA: --php-bin bir binary yolu gerektirir." >&2; exit 2; }
      EXTRA_BINS+=("$2"); shift 2 ;;
    --php-bin=*)
      EXTRA_BINS+=("${1#--php-bin=}"); shift ;;
    --version) echo "$SCRIPT_NAME $VERSION"; exit 0 ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    -*) echo "HATA: bilinmeyen seçenek: $1 (yardım için --help)" >&2; exit 2 ;;
    *) echo "HATA: bilinmeyen argüman: $1 (yardım için --help)" >&2; exit 2 ;;
  esac
done

case "$PROFILE" in
  minimal|standard|strict) ;;
  *) echo "HATA: geçersiz profil '$PROFILE' (minimal|standard|strict kullanın)." >&2; exit 2 ;;
esac

if (( RELOAD == 1 )) && [[ "$MODE" != "apply" ]]; then
  echo "UYARI: --reload yalnızca --apply ile anlamlıdır; bu çalışmada yoksayıldı." >&2
  RELOAD=0
fi

if (( RESTART == 1 )) && [[ "$MODE" != "apply" ]]; then
  echo "UYARI: --restart yalnızca --apply ile anlamlıdır; bu çalışmada yoksayıldı." >&2
  RESTART=0
fi

if (( RESTART == 1 && RELOAD == 1 )); then
  echo "BİLGİ: --restart verildi; --reload yerine tam restart yapılacak." >&2
  RELOAD=0
fi

if (( CVE_MITIGATE == 0 )); then
  if [[ "$POST_MAX_SIZE" != "32M" || -n "$UPLOAD_MAX_FILESIZE" ]]; then
    echo "UYARI: --post-max-size/--upload-max-filesize yalnızca --cve-mitigate ile anlamlıdır; yoksayıldı." >&2
  fi
fi

if (( ENFORCE_POOLS == 0 )); then
  if (( POOL_MEMORY_UNLIMITED == 1 || POOL_MAX_REQUESTS_1 == 1 )); then
    echo "UYARI: --pool-memory-unlimited/--pool-max-requests-1 yalnızca --enforce-pools ile anlamlıdır; yoksayıldı." >&2
    POOL_MEMORY_UNLIMITED=0
    POOL_MAX_REQUESTS_1=0
  fi
  if ((${#EXTRA_POOLS[@]} > 0)); then
    echo "UYARI: --pool-conf yalnızca --enforce-pools ile anlamlıdır; yoksayıldı." >&2
    EXTRA_POOLS=()
  fi
fi

if (( POOL_MEMORY_UNLIMITED == 1 )); then
  echo "DİKKAT: --pool-memory-unlimited havuzlara memory_limit=-1 yazacak." >&2
  echo "DİKKAT: cgroup/container limiti yoksa tek istek tüm RAM'i tüketebilir (DoS riski)." >&2
  echo "DİKKAT: yama sonrası gerçek limite dönün." >&2
fi

if (( POOL_MAX_REQUESTS_1 == 1 )); then
  echo "DİKKAT: --pool-max-requests-1 her worker'ı tek istek sonrası öldürecek; ciddi performans kaybı olur." >&2
fi

NEEDS_ROOT=0
[[ "$MODE" == "apply" || "$MODE" == "restore" ]] && NEEDS_ROOT=1
(( RELOAD == 1 || RESTART == 1 )) && NEEDS_ROOT=1
if (( NEEDS_ROOT == 1 )) && [[ "${EUID:-$(id -u)}" -ne 0 && "${HARDENING_ALLOW_NON_ROOT:-0}" != "1" ]]; then
  echo "HATA: bu işlem root gerektirir (mod: $MODE). Root olarak çalıştırın." >&2
  exit 1
fi
if (( NEEDS_ROOT == 1 )) && [[ "${HARDENING_ALLOW_NON_ROOT:-0}" == "1" && "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "UYARI: HARDENING_ALLOW_NON_ROOT=1 ile root kontrolü atlandı (yalnızca test için)." >&2
fi

if (( DISABLE_COLOR == 1 )) || [[ -n "${NO_COLOR:-}" ]] || [[ ! -t 1 ]]; then
  GREEN=''; RED=''; YELLOW=''; CYAN=''; RESET=''
else
  GREEN=$'\033[0;32m'; RED=$'\033[0;31m'; YELLOW=$'\033[0;33m'; CYAN=$'\033[0;36m'; RESET=''
fi

print_ok()   { printf '%b[OK]%b %s\n' "$GREEN" "$RESET" "$*"; }
print_fail() { printf '%b[FAIL]%b %s\n' "$RED" "$RESET" "$*"; }
print_warn() { printf '%b[UYARI]%b %s\n' "$YELLOW" "$RESET" "$*"; }
print_info() { printf '%b[INFO]%b %s\n' "$CYAN" "$RESET" "$*"; }

is_off_value() {
  local value
  value="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
  [[ "$value" == 'off' || "$value" == '0' || "$value" == 'false' || "$value" == 'no' ]]
}

is_on_value() {
  local value
  value="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
  [[ "$value" == 'on' || "$value" == '1' || "$value" == 'true' || "$value" == 'yes' ]]
}

trim_spaces() {
  sed -E 's/^[[:space:]]*//; s/[[:space:]]*$//'
}

confirm_or_abort() {
  if (( ASSUME_YES == 1 )); then
    return 0
  fi
  local ans=""
  read -r -p "Devam edilsin mi? [y/N] " ans || true
  if [[ "$ans" == "y" || "$ans" == "Y" ]]; then
    return 0
  fi
  echo "Vazgeçildi; hiçbir dosya değiştirilmedi."
  exit 0
}

# ---------------------------------------------------------------------------
# Boyut (32M/8M/1G) ve sürüm (8.1) yardımcıları
# ---------------------------------------------------------------------------
is_valid_size() {
  [[ "${1:-}" =~ ^[0-9]+[KkMmGg]?$ ]]
}

# "32M" -> bayt. Döndürür: stdout bayt, rc 0; geçersizse rc 1.
size_to_bytes() {
  local raw="$1" num suf mult
  raw="$(printf '%s' "$raw" | tr -d '[:space:]')"
  [[ "$raw" =~ ^([0-9]+)([KkMmGg])?$ ]] || return 1
  num="${BASH_REMATCH[1]}"
  suf="${BASH_REMATCH[2]:-}"
  mult=1
  case "$suf" in
    K|k) mult=1024 ;;
    M|m) mult=1048576 ;;
    G|g) mult=1073741824 ;;
  esac
  printf '%s' "$((num * mult))"
}

fmt_bytes() {
  local b="$1"
  if (( b % 1073741824 == 0 && b > 0 )); then
    printf '%sG' "$((b / 1073741824))"
  elif (( b % 1048576 == 0 && b > 0 )); then
    printf '%sM' "$((b / 1048576))"
  elif (( b % 1024 == 0 && b > 0 )); then
    printf '%sK' "$((b / 1024))"
  else
    printf '%s' "$b"
  fi
}

# "8.1" >= "8.5" mi? major.minor sayısal karşılaştırma. Boş sürüm her zaman false.
version_gte() {
  local have="${1:-}" want="${2:-}"
  local have_maj have_min want_maj want_min
  [[ "$have" =~ ^([0-9]+)\.([0-9]+) ]] || return 1
  have_maj="${BASH_REMATCH[1]}"
  have_min="${BASH_REMATCH[2]}"
  [[ "$want" =~ ^([0-9]+)\.([0-9]+) ]] || return 1
  want_maj="${BASH_REMATCH[1]}"
  want_min="${BASH_REMATCH[2]}"
  if (( have_maj > want_maj )); then return 0; fi
  if (( have_maj < want_maj )); then return 1; fi
  (( have_min >= want_min ))
}

# INI yolundaki sürüm ipuçlarından "major.minor" tahmin eder (bulamazsa boş döner).
guess_version_from_path() {
  local p="$1"
  if [[ "$p" =~ ea-php([0-9])([0-9]+) ]]; then
    printf '%s.%s' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
    return 0
  fi
  if [[ "$p" =~ alt/php([0-9])([0-9]+) ]]; then
    printf '%s.%s' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
    return 0
  fi
  if [[ "$p" =~ /usr/local/php([0-9])([0-9]+)/ ]]; then
    printf '%s.%s' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
    return 0
  fi
  if [[ "$p" =~ plesk/php/([0-9]+)\.([0-9]+) ]]; then
    printf '%s.%s' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
    return 0
  fi
  if [[ "$p" =~ /etc/php/([0-9]+)\.([0-9]+)/ ]]; then
    printf '%s.%s' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
    return 0
  fi
  if [[ "$p" =~ php-?([0-9]+)\.([0-9]+) ]]; then
    printf '%s.%s' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
    return 0
  fi
  if [[ "$p" =~ php([0-9])([0-9]) ]]; then
    printf '%s.%s' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
    return 0
  fi
  printf ''
}

# ---------------------------------------------------------------------------
# Panel tespiti
# ---------------------------------------------------------------------------
panels=()
[[ -d /usr/local/cpanel && ( -e /usr/local/cpanel/cpanel || -e /usr/local/cpanel/version ) ]] && panels+=("cPanel/WHM")
[[ -d /usr/local/directadmin && ( -e /usr/local/directadmin/conf/directadmin.conf || -x /usr/local/directadmin/directadmin ) ]] && panels+=("DirectAdmin")
[[ -e /usr/local/psa/version || -x /usr/bin/plesk || -x /usr/sbin/plesk ]] && panels+=("Plesk")
if ((${#panels[@]} == 0)); then panels+=("Bilinmeyen/genel Linux PHP kurulumu"); fi

printf 'Panel tespiti: %s\n' "$(IFS=', '; echo "${panels[*]}")"
_cve_state="kapalı"
if (( CVE_MITIGATE == 1 )); then _cve_state="açık (post_max_size=$POST_MAX_SIZE)"; fi
printf 'Betik: %s v%s | Mod: %s | Profil: %s | CVE-2026-109618/109619 azaltma: %s\n\n' \
  "$SCRIPT_NAME" "$VERSION" "$MODE" "$PROFILE" "$_cve_state"

# ---------------------------------------------------------------------------
# Profil verisi: yönetilen boolean direktifler + disable_functions listeleri
# ---------------------------------------------------------------------------
STANDARD_DISABLE_FUNCTIONS="exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec,show_source"
STRICT_EXTRA_DISABLE_FUNCTIONS="symlink,link,apache_child_terminate,apache_setenv,define_syslog_variables,posix_kill,posix_mkfifo,posix_setpgid,posix_setsid,posix_setuid,posix_setgid,posix_uname,proc_close,proc_get_status,proc_nice,proc_terminate,pcntl_fork,pcntl_signal,pcntl_signal_dispatch,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_alarm,pcntl_waitpid,pcntl_wexitstatus,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wtermsig,pcntl_wstopsig,pcntl_get_last_error,pcntl_strerror,pcntl_async_signals,expect_popen"

MANAGED_BOOL_KEYS=()
declare -A EXPECTED_BOOL=()
REQUIRED_FUNCS=()

case "$PROFILE" in
  minimal)
    MANAGED_BOOL_KEYS=("session.upload_progress.enabled")
    EXPECTED_BOOL["session.upload_progress.enabled"]="Off"
    ;;
  standard)
    MANAGED_BOOL_KEYS=(
      "session.upload_progress.enabled"
      "session.upload_progress.cleanup"
      "expose_php"
      "allow_url_include"
    )
    EXPECTED_BOOL["session.upload_progress.enabled"]="Off"
    EXPECTED_BOOL["session.upload_progress.cleanup"]="On"
    EXPECTED_BOOL["expose_php"]="Off"
    EXPECTED_BOOL["allow_url_include"]="Off"
    IFS=',' read -r -a REQUIRED_FUNCS <<< "$STANDARD_DISABLE_FUNCTIONS"
    ;;
  strict)
    MANAGED_BOOL_KEYS=(
      "session.upload_progress.enabled"
      "session.upload_progress.cleanup"
      "expose_php"
      "allow_url_include"
      "display_errors"
      "log_errors"
    )
    EXPECTED_BOOL["session.upload_progress.enabled"]="Off"
    EXPECTED_BOOL["session.upload_progress.cleanup"]="On"
    EXPECTED_BOOL["expose_php"]="Off"
    EXPECTED_BOOL["allow_url_include"]="Off"
    EXPECTED_BOOL["display_errors"]="Off"
    EXPECTED_BOOL["log_errors"]="On"
    IFS=',' read -r -a REQUIRED_FUNCS <<< "${STANDARD_DISABLE_FUNCTIONS},${STRICT_EXTRA_DISABLE_FUNCTIONS}"
    ;;
esac

MANAGES_FUNCS=0
if ((${#REQUIRED_FUNCS[@]} > 0)); then MANAGES_FUNCS=1; fi

# ---------------------------------------------------------------------------
# CVE-2026-109618/109619 katmanı (--cve-mitigate): boyut + girdi limitleri.
# Sıkılaştırma kuralı: mevcut değer hedeften katıysa (küçükse) korunur,
# gevşekse hedefe çekilir; asla gevşetme yapılmaz.
# ---------------------------------------------------------------------------
MANAGED_SIZE_KEYS=()
MANAGED_INT_KEYS=()
declare -A CVE_EXPECTED=()

if (( CVE_MITIGATE == 1 )); then
  if ! is_valid_size "$POST_MAX_SIZE"; then
    echo "HATA: geçersiz --post-max-size değeri: '$POST_MAX_SIZE' (örn: 8M, 32M, 1G)." >&2
    exit 2
  fi
  _post_bytes="$(size_to_bytes "$POST_MAX_SIZE")"
  if (( _post_bytes <= 0 )); then
    echo "HATA: --post-max-size 0 olamaz (0 = sınırsız demektir)." >&2
    exit 2
  fi
  if [[ -z "$UPLOAD_MAX_FILESIZE" ]]; then
    # Varsayılan: post_max_size'ın 1M altı (küçük post değerlerinde yarısı).
    if (( _post_bytes > 2097152 )); then
      _up_bytes=$((_post_bytes - 1048576))
    else
      _up_bytes=$((_post_bytes / 2))
    fi
    if (( _up_bytes <= 0 )); then _up_bytes=1024; fi
    UPLOAD_MAX_FILESIZE="$(fmt_bytes "$_up_bytes")"
  else
    if ! is_valid_size "$UPLOAD_MAX_FILESIZE"; then
      echo "HATA: geçersiz --upload-max-filesize değeri: '$UPLOAD_MAX_FILESIZE' (örn: 7M)." >&2
      exit 2
    fi
    _up_bytes="$(size_to_bytes "$UPLOAD_MAX_FILESIZE")"
    if (( _up_bytes <= 0 || _up_bytes >= _post_bytes )); then
      echo "HATA: --upload-max-filesize ($UPLOAD_MAX_FILESIZE) --post-max-size ($POST_MAX_SIZE) değerinden küçük olmalıdır." >&2
      exit 2
    fi
  fi
  MANAGED_SIZE_KEYS=("post_max_size" "upload_max_filesize")
  CVE_EXPECTED["post_max_size"]="$POST_MAX_SIZE"
  CVE_EXPECTED["upload_max_filesize"]="$UPLOAD_MAX_FILESIZE"
  MANAGED_INT_KEYS=("max_input_vars" "max_input_nesting_level" "max_file_uploads")
  CVE_EXPECTED["max_input_vars"]="1000"
  CVE_EXPECTED["max_input_nesting_level"]="64"
  CVE_EXPECTED["max_file_uploads"]="20"
  # PHP 8.5+ doğrulanmış fatal-backtrace yolu için (sürüm kapısı aşağıda).
  MANAGED_BOOL_KEYS+=("fatal_error_backtraces")
  EXPECTED_BOOL["fatal_error_backtraces"]="0"
  printf 'CVE katmanı hedefleri: post_max_size=%s, upload_max_filesize=%s,' "$POST_MAX_SIZE" "$UPLOAD_MAX_FILESIZE"
  printf ' max_input_vars=1000, max_input_nesting_level=64, max_file_uploads=20\n\n'
fi

# ---------------------------------------------------------------------------
# Sürüm kapısı: anahtar -> gereken en düşük "major.minor". Tabloda olmayan
# anahtarlar tüm sürümlere uygulanır. Sürümü bilinmeyen dosyalarda 8.x kapılı
# anahtarlar atlanır (bilinmeyen direktif her istekte uyarı üretir ve 109619
# için tetikleyici olabilir), eski kapılı anahtarlar uygulanır.
# ---------------------------------------------------------------------------
declare -A KEY_MIN_VERSION=(
  ["session.upload_progress.enabled"]="5.4"
  ["session.upload_progress.cleanup"]="5.4"
  ["max_input_vars"]="5.4"
  ["fatal_error_backtraces"]="8.5"
)
declare -A INI_VERSIONS=()

version_of_ini() {
  printf '%s' "${INI_VERSIONS[$1]:-}"
}

set_ini_version() {
  INI_VERSIONS[$1]="$2"
}

set_ini_version_default() {
  local ini="$1" ver="$2"
  if [[ -z "${INI_VERSIONS[$ini]:-}" && -n "$ver" ]]; then
    INI_VERSIONS[$ini]="$ver"
  fi
}

key_applies_to_version() {
  local key="$1" have="$2" min
  min="${KEY_MIN_VERSION[$key]:-0}"
  if [[ "$min" == "0" ]]; then return 0; fi
  if [[ -z "$have" ]]; then
    if version_gte "$min" "8.0"; then return 1; fi
    return 0
  fi
  version_gte "$have" "$min"
}

key_applies_to_ini() {
  key_applies_to_version "$1" "$(version_of_ini "$2")"
}

# ---------------------------------------------------------------------------
# INI okuma yardımcıları
# ---------------------------------------------------------------------------
# Aktif (yorum satırı olmayan) "anahtar = ..." satırlarını eşleştiren regex üretir.
key_regex() {
  local esc="${1//./\\.}"
  printf '^[[:space:]]*%s[[:space:]]*=' "$esc"
}

strip_ini_value() {
  sed -E 's/^[^=]*=[[:space:]]*//; s/[;#].*$//; s/^[[:space:]]*//; s/[[:space:]]*$//'
}

# Bir anahtarın aktif değerlerini satır satır yazdırır (bulunamazsa çıktı üretmez).
ini_active_values() {
  local ini="$1" key="$2"
  grep -E "$(key_regex "$key")" "$ini" 2>/dev/null | strip_ini_value || true
}

ini_active_count() {
  local ini="$1" key="$2"
  grep -c -E "$(key_regex "$key")" "$ini" 2>/dev/null || true
}

# disable_functions aktif satırlarındaki token'ları küçük harfe çevirip tekilleştirir.
ini_disable_tokens() {
  local ini="$1" line tok
  declare -A seen=()
  while IFS= read -r line; do
    line="$(printf '%s' "$line" | sed -e 's/["'"'"']//g' | tr ',' '\n')"
    while IFS= read -r tok; do
      tok="$(printf '%s' "$tok" | tr '[:upper:]' '[:lower:]' | trim_spaces)"
      [[ -z "$tok" ]] && continue
      [[ -n "${seen[$tok]+x}" ]] && continue
      seen[$tok]=1
      printf '%s\n' "$tok"
    done <<< "$line"
  done < <(ini_active_values "$ini" "disable_functions")
}

# Profilin zorunlu kıldığı ama dosyada eksik olan fonksiyonları listeler.
missing_disable_tokens() {
  local ini="$1" tok
  declare -A have=()
  while IFS= read -r tok; do
    [[ -n "$tok" ]] && have[$tok]=1
  done < <(ini_disable_tokens "$ini")
  if ((${#REQUIRED_FUNCS[@]} > 0)); then
    for tok in "${REQUIRED_FUNCS[@]}"; do
      [[ -n "${have[$tok]+x}" ]] || printf '%s\n' "$tok"
    done
  fi
}

# Mevcut token'lar + profilin zorunluları birleştirilmiş, deterministik CSV üretir.
merged_disable_csv() {
  local ini="$1" tok
  declare -A seen=()
  local -a out=() extras=()
  if ((${#REQUIRED_FUNCS[@]} > 0)); then
    for tok in "${REQUIRED_FUNCS[@]}"; do
      [[ -n "${seen[$tok]+x}" ]] && continue
      seen[$tok]=1
      out+=("$tok")
    done
  fi
  while IFS= read -r tok; do
    [[ -z "$tok" || -n "${seen[$tok]+x}" ]] && continue
    seen[$tok]=1
    extras+=("$tok")
  done < <(ini_disable_tokens "$ini")
  if ((${#extras[@]} > 0)); then
    while IFS= read -r tok; do
      out+=("$tok")
    done < <(printf '%s\n' "${extras[@]}" | LC_ALL=C sort -u)
  fi
  local IFS=','
  printf '%s' "${out[*]}"
}

bool_matches_expected() {
  local value="$1" expected="$2"
  if [[ "$expected" == "On" ]]; then
    is_on_value "$value"
  else
    is_off_value "$value"
  fi
}

# Boyut değerini bayta çevirir. "0" PHP'de sınırsız demektir -> INF yazar.
# Çıktı: bayt | INF | UNKNOWN (ayrıştırılamazsa).
ini_size_bytes() {
  local value="$1" b
  value="$(printf '%s' "$value" | tr -d '[:space:]')"
  if [[ -z "$value" ]]; then printf 'UNKNOWN'; return 0; fi
  if ! b="$(size_to_bytes "$value" 2>/dev/null)"; then printf 'UNKNOWN'; return 0; fi
  if (( b == 0 )); then printf 'INF'; return 0; fi
  printf '%s' "$b"
}

# Düz tamsayı değerini okur (max_input_vars vb.). Çıktı: sayı | UNKNOWN.
ini_int_value() {
  local value="$1"
  value="$(printf '%s' "$value" | tr -d '[:space:]')"
  if [[ "$value" =~ ^-?[0-9]+$ ]]; then printf '%s' "$value"; else printf 'UNKNOWN'; fi
}

# Sıkılaştırma kontrolü: mevcut <= hedef ise 0 (yeterli), değilse 1.
size_tight_enough() {
  local current="$1" expected_bytes="$2" cur
  cur="$(ini_size_bytes "$current")"
  if [[ "$cur" == "INF" || "$cur" == "UNKNOWN" ]]; then return 1; fi
  (( cur <= expected_bytes ))
}

int_tight_enough() {
  local current="$1" expected="$2" cur
  cur="$(ini_int_value "$current")"
  if [[ "$cur" == "UNKNOWN" ]]; then return 1; fi
  (( cur <= expected ))
}

# ---------------------------------------------------------------------------
# PHP binary / INI keşfi
# ---------------------------------------------------------------------------
declare -A seen_bins=()
declare -A seen_ini=()
PHP_BINS=()
INI_FILES=()

# Bu çalıştırılabilir gerçekten PHP CLI mı? (Bazı sistemlerde /usr/bin/php = php-cgi.)
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

add_bin() {
  local p="$1"
  [[ -x "$p" && ! -d "$p" ]] || return 0
  [[ -n "${seen_bins[$p]+x}" ]] && return 0
  seen_bins[$p]=1

  if ! is_php_cli "$p"; then
    if [[ "$p" == '/usr/bin/php' || "$p" == '/usr/local/bin/php' ]]; then
      print_warn "$p PHP CLI değil veya -r desteklemiyor (muhtemelen php-cgi); doğrulamaya alınmadı."
    fi
    return 0
  fi
  PHP_BINS+=("$p")
}

canonical_ini_path() {
  readlink -f -- "$1" 2>/dev/null || printf '%s' "$1"
}

add_ini() {
  local p="$1" real
  [[ -f "$p" && -r "$p" ]] || return 0
  real="$(canonical_ini_path "$p")"
  [[ -f "$real" && -r "$real" ]] || return 0
  [[ -n "${seen_ini[$real]+x}" ]] && return 0
  seen_ini[$real]=1
  INI_FILES+=("$real")
  set_ini_version_default "$real" "$(guess_version_from_path "$p")"
}

# Taranan ek .ini dosyaları yalnızca yönetilen bir direktifi açıkça ayarlıyorsa dahil edilir.
SCAN_KEYS=("${MANAGED_BOOL_KEYS[@]}")
if (( MANAGES_FUNCS == 1 )); then SCAN_KEYS+=("disable_functions"); fi
if ((${#MANAGED_SIZE_KEYS[@]} > 0)); then SCAN_KEYS+=("${MANAGED_SIZE_KEYS[@]}"); fi
if ((${#MANAGED_INT_KEYS[@]} > 0)); then SCAN_KEYS+=("${MANAGED_INT_KEYS[@]}"); fi
declare -A BIN_VERSIONS=()
scan_alt=""
for _k in "${SCAN_KEYS[@]}"; do
  _esc="${_k//./\\.}"
  if [[ -z "$scan_alt" ]]; then scan_alt="$_esc"; else scan_alt="$scan_alt|$_esc"; fi
done
SCAN_REGEX="^[[:space:]]*(${scan_alt})[[:space:]]*="

if ((${#EXTRA_BINS[@]} > 0)); then
  for _b in "${EXTRA_BINS[@]}"; do add_bin "$_b"; done
fi

# cPanel/EasyApache, CloudLinux alt-php, DirectAdmin CustomBuild, Plesk ve OS paketleri.
for _bin in \
  /usr/local/bin/ea-php[0-9][0-9] \
  /opt/cpanel/ea-php*/root/usr/bin/php \
  /opt/alt/php*/usr/bin/php \
  /usr/local/php*/bin/php \
  /opt/plesk/php/*/bin/php \
  /usr/bin/php /usr/bin/php[0-9].[0-9] \
  /usr/local/bin/php; do
  add_bin "$_bin"
done

printf 'Bulunan PHP CLI sürümleri:\n'
if ((${#PHP_BINS[@]} == 0)); then
  echo '  PHP CLI binary bulunamadı; bilinen yapılandırma yolları taranacak.'
else
  for _bin in "${PHP_BINS[@]}"; do
    _version="$("$_bin" -r 'echo PHP_VERSION;' 2>/dev/null || printf 'bilinmiyor')"
    _majmin="$("$_bin" -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null || true)"
    if [[ "$_majmin" =~ ^[0-9]+\.[0-9]+$ ]]; then BIN_VERSIONS[$_bin]="$_majmin"; fi
    _ini="$("$_bin" -r 'echo php_ini_loaded_file() ?: "(php.ini yüklenmemiş)";' 2>/dev/null || printf 'belirlenemedi')"
    printf '  PHP %-10s binary=%s\n    ini=%s\n' "${_version:-bilinmiyor}" "$_bin" "${_ini:-belirlenemedi}"
    if [[ -n "$_ini" && "$_ini" != '(php.ini yüklenmemiş)' && "$_ini" != 'belirlenemedi' ]]; then
      add_ini "$_ini"
      if [[ -n "${_majmin:-}" && "$_majmin" =~ ^[0-9]+\.[0-9]+$ ]]; then
        set_ini_version "$(canonical_ini_path "$_ini")" "$_majmin"
      fi
    fi

    _scanned="$("$_bin" -r 'echo php_ini_scanned_files() ?: "";' 2>/dev/null || true)"
    if [[ -n "$_scanned" ]]; then
      while IFS= read -r _scanfile; do
        [[ -n "$_scanfile" ]] || continue
        if [[ -f "$_scanfile" ]] && grep -Eq "$SCAN_REGEX" "$_scanfile"; then
          add_ini "$_scanfile"
        fi
      done < <(printf '%s' "$_scanned" | tr ';,' '\n' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
    fi
  done
fi

# Eşleşen CLI binary sunmayan kurulumlar için bilinen ana php.ini yolları.
for _ini in \
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
  add_ini "$_ini"
done

if ((${#EXTRA_INIS[@]} > 0)); then
  for _ini in "${EXTRA_INIS[@]}"; do
    if [[ -f "$_ini" && -r "$_ini" ]]; then
      add_ini "$_ini"
    else
      print_warn "--ini ile verilen dosya okunamadı, atlandı: $_ini"
    fi
  done
fi

if [[ " ${INI_FILES[*]:-} " == *" /opt/alt/"* ]]; then
  print_info "CloudLinux alt-php yolu tespit edildi; PHP Selector sürümleri kapsama dahil."
fi

# ---------------------------------------------------------------------------
# Bulunan INI dosyaları + durum özeti
# ---------------------------------------------------------------------------
printf '\nBulunan PHP yapılandırma dosyaları (%d) [profil: %s]:\n' "${#INI_FILES[@]}" "$PROFILE"
if ((${#INI_FILES[@]} == 0)); then
  print_fail 'php.ini bulunamadı. Hiçbir dosya değiştirilmedi.'
  exit 1
fi

describe_bool_state() {
  local ini="$1" key="$2" expected="$3"
  local count vals val
  count="$(ini_active_count "$ini" "$key")"
  if [[ "$count" == "0" ]]; then
    printf 'ayar yok; eklenecek (%s)' "$expected"
    return 0
  fi
  if [[ "$count" != "1" ]]; then
    printf 'DİKKAT: %s etkin satır var; tekilleştirilecek' "$count"
    return 0
  fi
  vals="$(ini_active_values "$ini" "$key")"
  val="$(printf '%s' "$vals" | head -n1)"
  if bool_matches_expected "$val" "$expected"; then
    printf 'zaten %s' "${val:-boş}"
  else
    printf 'değişecek: %s -> %s' "${val:-boş}" "$expected"
  fi
}

describe_funcs_state() {
  local ini="$1"
  local count miss missing_csv
  count="$(ini_active_count "$ini" "disable_functions")"
  miss="$(missing_disable_tokens "$ini" | tr '\n' ',' | sed 's/,$//')"
  if [[ -z "$miss" && "$count" == "1" ]]; then
    printf 'tamam; zorunlu fonksiyonların tümü kapalı'
  elif [[ -z "$miss" ]]; then
    printf 'DİKKAT: %s etkin satır var; tekilleştirilecek' "$count"
  elif [[ "$count" == "0" ]]; then
    printf 'ayar yok; eklenecek (eksik: %s)' "$miss"
  else
    missing_csv="$miss"
    printf 'birleştirilecek (eksik: %s)' "$missing_csv"
  fi
}

describe_size_state() {
  local ini="$1" key="$2" expected="$3"
  local count val exp_bytes
  count="$(ini_active_count "$ini" "$key")"
  exp_bytes="$(size_to_bytes "$expected")"
  if [[ "$count" == "0" ]]; then
    printf 'ayar yok; eklenecek (%s)' "$expected"
    return 0
  fi
  if [[ "$count" != "1" ]]; then
    printf 'DİKKAT: %s etkin satır var; tekilleştirilecek (hedef: %s)' "$count" "$expected"
    return 0
  fi
  val="$(ini_active_values "$ini" "$key" | head -n1)"
  if size_tight_enough "$val" "$exp_bytes"; then
    printf 'zaten yeterli (%s <= %s)' "${val:-boş}" "$expected"
  else
    printf 'sıkılaştırılacak: %s -> %s' "${val:-boş}" "$expected"
  fi
}

describe_int_state() {
  local ini="$1" key="$2" expected="$3"
  local count val
  count="$(ini_active_count "$ini" "$key")"
  if [[ "$count" == "0" ]]; then
    printf 'ayar yok; eklenecek (%s)' "$expected"
    return 0
  fi
  if [[ "$count" != "1" ]]; then
    printf 'DİKKAT: %s etkin satır var; tekilleştirilecek (hedef: %s)' "$count" "$expected"
    return 0
  fi
  val="$(ini_active_values "$ini" "$key" | head -n1)"
  if int_tight_enough "$val" "$expected"; then
    printf 'zaten yeterli (%s <= %s)' "${val:-boş}" "$expected"
  else
    printf 'sıkılaştırılacak: %s -> %s' "${val:-boş}" "$expected"
  fi
}

skip_note() {
  local key="$1" ini="$2" have
  have="$(version_of_ini "$ini")"
  if [[ -z "$have" ]]; then have="bilinmiyor"; fi
  printf 'atlandı: PHP %s+ gerektirir (bu dosya: %s)' "${KEY_MIN_VERSION[$key]}" "$have"
}

# CVE katmanı açıkken yönetilmeyen ama ilgili ayarların mevcut durumunu gösterir.
describe_cve_info() {
  local ini="$1" have count val
  have="$(version_of_ini "$ini")"
  count="$(ini_active_count "$ini" "memory_limit")"
  if [[ "$count" == "0" ]]; then
    printf '    %-33s [bilgi] ayar yok (PHP varsayılanı 128M); ini içinde yönetilmiyor\n' "memory_limit"
  else
    val="$(ini_active_values "$ini" "memory_limit" | head -n1)"
    printf '    %-33s [bilgi] mevcut: %s (%s etkin satır); ini içinde yönetilmiyor\n' "memory_limit" "${val:-boş}" "$count"
  fi
  printf '    %-33s [bilgi] -1 için --enforce-pools --pool-memory-unlimited (cgroup şart)\n' ""
  if [[ -z "$have" ]] || version_gte "$have" "8.4"; then
    count="$(ini_active_count "$ini" "max_multipart_body_parts")"
    if [[ "$count" == "0" ]]; then
      printf '    %-33s [bilgi] ayar yok (varsayılan -1 = sınırsız); sonlu değer önerilir\n' "max_multipart_body_parts"
    else
      val="$(ini_active_values "$ini" "max_multipart_body_parts" | head -n1)"
      printf '    %-33s [bilgi] mevcut: %s; sonlu değer önerilir\n' "max_multipart_body_parts" "${val:-boş}"
    fi
  fi
}

for _ini in "${INI_FILES[@]}"; do
  _iver="$(version_of_ini "$_ini")"
  if [[ -n "$_iver" ]]; then
    printf '  %s [PHP %s]\n' "$_ini" "$_iver"
  else
    printf '  %s [sürüm bilinmiyor]\n' "$_ini"
  fi
  for _key in "${MANAGED_BOOL_KEYS[@]}"; do
    if ! key_applies_to_ini "$_key" "$_ini"; then
      printf '    %-33s [%s]\n' "$_key" "$(skip_note "$_key" "$_ini")"
      continue
    fi
    printf '    %-33s [%s]\n' "$_key" "$(describe_bool_state "$_ini" "$_key" "${EXPECTED_BOOL[$_key]}")"
  done
  if ((${#MANAGED_SIZE_KEYS[@]} > 0)); then
    for _key in "${MANAGED_SIZE_KEYS[@]}"; do
      if ! key_applies_to_ini "$_key" "$_ini"; then
        printf '    %-33s [%s]\n' "$_key" "$(skip_note "$_key" "$_ini")"
        continue
      fi
      printf '    %-33s [%s]\n' "$_key" "$(describe_size_state "$_ini" "$_key" "${CVE_EXPECTED[$_key]}")"
    done
  fi
  if ((${#MANAGED_INT_KEYS[@]} > 0)); then
    for _key in "${MANAGED_INT_KEYS[@]}"; do
      if ! key_applies_to_ini "$_key" "$_ini"; then
        printf '    %-33s [%s]\n' "$_key" "$(skip_note "$_key" "$_ini")"
        continue
      fi
      printf '    %-33s [%s]\n' "$_key" "$(describe_int_state "$_ini" "$_key" "${CVE_EXPECTED[$_key]}")"
    done
  fi
  if (( MANAGES_FUNCS == 1 )); then
    printf '    %-33s [%s]\n' "disable_functions" "$(describe_funcs_state "$_ini")"
  fi
  if (( CVE_MITIGATE == 1 )); then
    describe_cve_info "$_ini"
  fi
done

# ---------------------------------------------------------------------------
# PHP-FPM havuz keşfi + override taraması
# ---------------------------------------------------------------------------
POOL_FILES=()
declare -A seen_pools=()

add_pool() {
  local p="$1" real
  [[ -f "$p" && -r "$p" ]] || return 0
  real="$(readlink -f -- "$p" 2>/dev/null || printf '%s' "$p")"
  [[ -f "$real" && -r "$real" ]] || return 0
  [[ -n "${seen_pools[$real]+x}" ]] && return 0
  seen_pools[$real]=1
  POOL_FILES+=("$real")
}

discover_pool_files() {
  local _pool
  for _pool in \
    /etc/php/*/fpm/pool.d/*.conf \
    /opt/cpanel/ea-php*/root/etc/php-fpm.d/*.conf \
    /usr/local/php*/etc/php-fpm.d/*.conf \
    /opt/alt/php*/etc/php-fpm.d/*.conf \
    /opt/plesk/php/*/etc/php-fpm.d/*.conf \
    /usr/local/directadmin/data/users/*/php/*.conf; do
    add_pool "$_pool"
  done
  if ((${#EXTRA_POOLS[@]} > 0)); then
    for _pool in "${EXTRA_POOLS[@]}"; do
      if [[ -f "$_pool" && -r "$_pool" ]]; then
        add_pool "$_pool"
      else
        print_warn "--pool-conf ile verilen dosya okunamadı, atlandı: $_pool"
      fi
    done
  fi
}

discover_pool_files

# Havuzda zorlanacak ayarlar: "tür|anahtar|değer" (tür: admin_value | pool).
POOL_SPECS=()
if (( ENFORCE_POOLS == 1 )); then
  POOL_SPECS+=("admin_value|session.upload_progress.enabled|Off")
  if (( POOL_MEMORY_UNLIMITED == 1 )); then
    POOL_SPECS+=("admin_value|memory_limit|-1")
  fi
  if (( POOL_MAX_REQUESTS_1 == 1 )); then
    POOL_SPECS+=("pool|pm.max_requests|1")
  fi
fi

# Havuzdaki aktif satırları eşleştiren regex (php_value/php_admin_value/php_admin_flag varyantları).
pool_key_regex() {
  local type="$1" key="$2" esc
  esc="${key//./\\.}"
  if [[ "$type" == "pool" ]]; then
    printf '^[[:space:]]*%s[[:space:]]*=' "$esc"
  else
    printf '^[[:space:]]*php_(admin_)?(value|flag)\\[%s\\][[:space:]]*=' "$esc"
  fi
}

pool_spec_line() {
  local type="$1" key="$2" value="$3"
  if [[ "$type" == "pool" ]]; then
    printf '%s = %s' "$key" "$value"
  else
    printf 'php_admin_value[%s] = %s' "$key" "$value"
  fi
}

scan_fpm_pools() {
  local pattern found=0
  pattern='^[[:space:]]*php_(admin_)?(value|flag)\[session\.upload_progress\.enabled\][[:space:]]*=[[:space:]]*(on|1|true|yes)'
  printf '\nPHP-FPM havuz dosyaları (%d) + override taraması:\n' "${#POOL_FILES[@]}"
  if ((${#POOL_FILES[@]} == 0)); then
    print_info "Havuz dosyası bulunamadı."
    return 0
  fi
  for _pool in "${POOL_FILES[@]}"; do
    if grep -Eq -i "$pattern" "$_pool" 2>/dev/null; then
      print_warn "$_pool bu ayarı tekrar AÇIYOR (php-fpm havuzu global php.ini'yi ezer):"
      grep -Hn -i -E "$pattern" "$_pool" 2>/dev/null | sed 's/^/      /' || true
      found=$((found+1))
    fi
  done
  if (( found == 0 )); then
    print_ok "upload-progress'i tekrar açan PHP-FPM havuz ayarı bulunamadı."
  else
    print_warn "$found havuz dosyası ayarı eziyor; bu dosyaları elle düzeltin (betik havuzları değiştirmez)."
  fi
}

# ---------------------------------------------------------------------------
# Doğrulama
# ---------------------------------------------------------------------------
verify_ini_file() {
  local ini="$1" key expected count val failed=0
  local -a vals=()
  for key in "${MANAGED_BOOL_KEYS[@]}"; do
    key_applies_to_ini "$key" "$ini" || continue
    expected="${EXPECTED_BOOL[$key]}"
    mapfile -t vals < <(ini_active_values "$ini" "$key" || true)
    count=${#vals[@]}
    if (( count != 1 )); then
      print_fail "$ini: $key etkin satır sayısı $count (beklenen: 1)."
      failed=1
      continue
    fi
    val="$(printf '%s' "${vals[0]}" | trim_spaces)"
    if bool_matches_expected "$val" "$expected"; then
      print_ok "$ini: $key = ${val:-boş} (dosya doğrulandı)"
    else
      print_fail "$ini: $key değeri '${val:-boş}'; $expected bekleniyordu."
      failed=1
    fi
  done
  if ((${#MANAGED_SIZE_KEYS[@]} > 0)); then
    for key in "${MANAGED_SIZE_KEYS[@]}"; do
      key_applies_to_ini "$key" "$ini" || continue
      expected="${CVE_EXPECTED[$key]}"
      mapfile -t vals < <(ini_active_values "$ini" "$key" || true)
      count=${#vals[@]}
      if (( count != 1 )); then
        print_fail "$ini: $key etkin satır sayısı $count (beklenen: 1)."
        failed=1
        continue
      fi
      val="$(printf '%s' "${vals[0]}" | trim_spaces)"
      if size_tight_enough "$val" "$(size_to_bytes "$expected")"; then
        print_ok "$ini: $key = ${val:-boş} (hedef $expected; dosya doğrulandı)"
      else
        print_fail "$ini: $key değeri '${val:-boş}' hedeften gevşek ($expected veya daha katı bekleniyordu)."
        failed=1
      fi
    done
  fi
  if ((${#MANAGED_INT_KEYS[@]} > 0)); then
    for key in "${MANAGED_INT_KEYS[@]}"; do
      key_applies_to_ini "$key" "$ini" || continue
      expected="${CVE_EXPECTED[$key]}"
      mapfile -t vals < <(ini_active_values "$ini" "$key" || true)
      count=${#vals[@]}
      if (( count != 1 )); then
        print_fail "$ini: $key etkin satır sayısı $count (beklenen: 1)."
        failed=1
        continue
      fi
      val="$(printf '%s' "${vals[0]}" | trim_spaces)"
      if int_tight_enough "$val" "$expected"; then
        print_ok "$ini: $key = ${val:-boş} (hedef $expected; dosya doğrulandı)"
      else
        print_fail "$ini: $key değeri '${val:-boş}' hedeften gevşek ($expected veya daha katı bekleniyordu)."
        failed=1
      fi
    done
  fi
  if (( MANAGES_FUNCS == 1 )); then
    count="$(ini_active_count "$ini" "disable_functions")"
    if [[ "$count" != "1" ]]; then
      print_fail "$ini: disable_functions etkin satır sayısı $count (beklenen: 1)."
      failed=1
    else
      local miss
      miss="$(missing_disable_tokens "$ini" | tr '\n' ',' | sed 's/,$//')"
      if [[ -z "$miss" ]]; then
        print_ok "$ini: disable_functions zorunlu listedeki tüm fonksiyonları içeriyor."
      else
        print_fail "$ini: disable_functions içinde eksik fonksiyonlar: $miss"
        failed=1
      fi
    fi
  fi
  return "$failed"
}

# php -i çıktısında "anahtar => local => master" satırını beklenen değere karşı kontrol eder.
cli_bool_ok() {
  local output="$1" key="$2" expected="$3"
  local esc line local_v master_v
  esc="${key//./\\.}"
  line="$(printf '%s\n' "$output" | grep -m1 -Ei "^[[:space:]]*${esc}[[:space:]]*=>" || true)"
  [[ -n "$line" ]] || return 2
  local_v="${line#*=>}"
  local_v="${local_v%%=>*}"
  master_v="${line##*=>}"
  local_v="$(printf '%s' "$local_v" | trim_spaces)"
  master_v="$(printf '%s' "$master_v" | trim_spaces)"
  if [[ "$expected" == "On" ]]; then
    is_on_value "$local_v" && is_on_value "$master_v"
  else
    is_off_value "$local_v" && is_off_value "$master_v"
  fi
}

# php -i çıktısında boyut/tamsayı direktifinin local+master değerlerini sıkılık
# kuralıyla kontrol eder: rc 0 yeterli, rc 1 gevşek, rc 2 satır yok.
cli_size_ok() {
  local output="$1" key="$2" expected_bytes="$3"
  local esc line local_v master_v
  esc="${key//./\\.}"
  line="$(printf '%s\n' "$output" | grep -m1 -Ei "^[[:space:]]*${esc}[[:space:]]*=>" || true)"
  [[ -n "$line" ]] || return 2
  local_v="${line#*=>}"
  local_v="${local_v%%=>*}"
  master_v="${line##*=>}"
  local_v="$(printf '%s' "$local_v" | trim_spaces)"
  master_v="$(printf '%s' "$master_v" | trim_spaces)"
  size_tight_enough "$local_v" "$expected_bytes" && size_tight_enough "$master_v" "$expected_bytes"
}

cli_int_ok() {
  local output="$1" key="$2" expected="$3"
  local esc line local_v master_v
  esc="${key//./\\.}"
  line="$(printf '%s\n' "$output" | grep -m1 -Ei "^[[:space:]]*${esc}[[:space:]]*=>" || true)"
  [[ -n "$line" ]] || return 2
  local_v="${line#*=>}"
  local_v="${local_v%%=>*}"
  master_v="${line##*=>}"
  local_v="$(printf '%s' "$local_v" | trim_spaces)"
  master_v="$(printf '%s' "$master_v" | trim_spaces)"
  int_tight_enough "$local_v" "$expected" && int_tight_enough "$master_v" "$expected"
}

# php -i çıktısına göre eksik disable_functions token'larını listeler (rc=2: satır yok).
cli_disable_missing() {
  local output="$1" line master tok
  declare -A have=()
  line="$(printf '%s\n' "$output" | grep -m1 -Ei '^[[:space:]]*disable_functions[[:space:]]*=>' || true)"
  [[ -n "$line" ]] || return 2
  master="${line##*=>}"
  if [[ ! "$master" =~ [Nn]o\ [Vv]alue ]]; then
    while IFS= read -r tok; do
      tok="$(printf '%s' "$tok" | tr '[:upper:]' '[:lower:]' | trim_spaces)"
      [[ -n "$tok" ]] && have[$tok]=1
    done < <(printf '%s' "$master" | tr ',' '\n')
  fi
  if ((${#REQUIRED_FUNCS[@]} > 0)); then
    for tok in "${REQUIRED_FUNCS[@]}"; do
      [[ -n "${have[$tok]+x}" ]] || printf '%s\n' "$tok"
    done
  fi
  return 0
}

verify_php_cli_settings() {
  local bin output version loaded_ini key expected rc
  local current_failed=0 checked=0

  if ((${#PHP_BINS[@]} == 0)); then
    print_fail 'Doğrulama için PHP CLI binary bulunamadı.'
    return 1
  fi

  printf '\nPHP CLI etkin ayar doğrulaması (php -i):\n'
  for bin in "${PHP_BINS[@]}"; do
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
    checked=$((checked+1))
    _binver="${BIN_VERSIONS[$bin]:-}"

    for key in "${MANAGED_BOOL_KEYS[@]}"; do
      key_applies_to_version "$key" "$_binver" || continue
      expected="${EXPECTED_BOOL[$key]}"
      if cli_bool_ok "$output" "$key" "$expected"; then
        print_ok "$bin (PHP $version): $key => $expected (local+master doğrulandı)"
      else
        rc=$?
        if (( rc == 2 )); then
          print_fail "$bin (PHP $version): php -i çıktısında $key bulunamadı. php.ini=${loaded_ini:-belirlenemedi}"
        else
          _raw="$(printf '%s\n' "$output" | grep -m1 -Ei "^[[:space:]]*${key//./\\.}[[:space:]]*=>" || true)"
          print_fail "$bin (PHP $version): $key beklenen değeri vermedi ($expected bekleniyordu): ${_raw:-satır yok}"
          printf '      php.ini: %s\n' "${loaded_ini:-belirlenemedi}"
        fi
        current_failed=1
      fi
    done

    if ((${#MANAGED_SIZE_KEYS[@]} > 0)); then
      for key in "${MANAGED_SIZE_KEYS[@]}"; do
        key_applies_to_version "$key" "$_binver" || continue
        expected="${CVE_EXPECTED[$key]}"
        if cli_size_ok "$output" "$key" "$(size_to_bytes "$expected")"; then
          print_ok "$bin (PHP $version): $key hedefi sağlıyor (<= $expected; local+master doğrulandı)"
        else
          rc=$?
          if (( rc == 2 )); then
            print_fail "$bin (PHP $version): php -i çıktısında $key bulunamadı. php.ini=${loaded_ini:-belirlenemedi}"
          else
            _raw="$(printf '%s\n' "$output" | grep -m1 -Ei "^[[:space:]]*${key//./\\.}[[:space:]]*=>" || true)"
            print_fail "$bin (PHP $version): $key hedeften gevşek ($expected veya daha katı bekleniyordu): ${_raw:-satır yok}"
            printf '      php.ini: %s\n' "${loaded_ini:-belirlenemedi}"
          fi
          current_failed=1
        fi
      done
    fi

    if ((${#MANAGED_INT_KEYS[@]} > 0)); then
      for key in "${MANAGED_INT_KEYS[@]}"; do
        key_applies_to_version "$key" "$_binver" || continue
        expected="${CVE_EXPECTED[$key]}"
        if cli_int_ok "$output" "$key" "$expected"; then
          print_ok "$bin (PHP $version): $key hedefi sağlıyor (<= $expected; local+master doğrulandı)"
        else
          rc=$?
          if (( rc == 2 )); then
            print_fail "$bin (PHP $version): php -i çıktısında $key bulunamadı. php.ini=${loaded_ini:-belirlenemedi}"
          else
            _raw="$(printf '%s\n' "$output" | grep -m1 -Ei "^[[:space:]]*${key//./\\.}[[:space:]]*=>" || true)"
            print_fail "$bin (PHP $version): $key hedeften gevşek ($expected veya daha katı bekleniyordu): ${_raw:-satır yok}"
            printf '      php.ini: %s\n' "${loaded_ini:-belirlenemedi}"
          fi
          current_failed=1
        fi
      done
    fi

    if (( MANAGES_FUNCS == 1 )); then
      _miss=""
      if ! _miss="$(cli_disable_missing "$output")"; then
        print_fail "$bin (PHP $version): php -i çıktısında disable_functions bulunamadı."
        current_failed=1
      elif [[ -n "$_miss" ]]; then
        print_fail "$bin (PHP $version): disable_functions içinde eksik: $(printf '%s' "$_miss" | tr '\n' ',' | sed 's/,$//')"
        printf '      php.ini: %s\n' "${loaded_ini:-belirlenemedi}"
        current_failed=1
      else
        print_ok "$bin (PHP $version): disable_functions zorunlu listedeki tüm fonksiyonları içeriyor."
      fi
    fi
    printf '      php.ini: %s\n' "${loaded_ini:-belirlenemedi}"
  done

  if (( checked == 0 )); then
    print_fail 'Hiçbir PHP CLI binary etkin ayar doğrulamasına ulaşamadı.'
    return 1
  fi
  return "$current_failed"
}

# ---------------------------------------------------------------------------
# Uygulama / geri yükleme / servis reload
# ---------------------------------------------------------------------------
apply_file() {
  local ini="$1" stamp="$2"
  local backup filter tmp tmp2 key merged
  backup="${ini}.${BACKUP_SUFFIX}-${stamp}"

  if ! cp -a -- "$ini" "$backup"; then
    echo "HATA: yedek alınamadı: $ini" >&2
    return 1
  fi

  filter="$(mktemp)" || { echo "HATA: geçici dosya oluşturulamadı: $ini" >&2; return 1; }
  if ! cp -- "$ini" "$filter"; then
    echo "HATA: dosya okunamadı: $ini (yedek: $backup)" >&2
    rm -f -- "$filter"
    return 1
  fi

  # Sıkılaştırma kuralı: hedeften katı olan mevcut tekil değerler korunur.
  declare -A KEEP_VALUE=()
  if ((${#MANAGED_SIZE_KEYS[@]} > 0)); then
    for key in "${MANAGED_SIZE_KEYS[@]}"; do
      key_applies_to_ini "$key" "$ini" || continue
      if [[ "$(ini_active_count "$ini" "$key")" == "1" ]]; then
        _cur="$(ini_active_values "$ini" "$key" | head -n1)"
        if size_tight_enough "$_cur" "$(size_to_bytes "${CVE_EXPECTED[$key]}")"; then
          KEEP_VALUE[$key]="$_cur"
        fi
      fi
    done
  fi
  if ((${#MANAGED_INT_KEYS[@]} > 0)); then
    for key in "${MANAGED_INT_KEYS[@]}"; do
      key_applies_to_ini "$key" "$ini" || continue
      if [[ "$(ini_active_count "$ini" "$key")" == "1" ]]; then
        _cur="$(ini_active_values "$ini" "$key" | head -n1)"
        if int_tight_enough "$_cur" "${CVE_EXPECTED[$key]}"; then
          KEEP_VALUE[$key]="$_cur"
        fi
      fi
    done
  fi

  # Yönetilen direktiflerin tüm aktif satırlarını kaldır (yorum satırlarına dokunma).
  for key in "${MANAGED_BOOL_KEYS[@]}"; do
    key_applies_to_ini "$key" "$ini" || continue
    tmp2="$(mktemp)" || { echo "HATA: geçici dosya oluşturulamadı: $ini" >&2; rm -f -- "$filter"; return 1; }
    grep -v -E "$(key_regex "$key")" "$filter" > "$tmp2" || true
    mv -f -- "$tmp2" "$filter"
  done
  if ((${#MANAGED_SIZE_KEYS[@]} > 0)); then
    for key in "${MANAGED_SIZE_KEYS[@]}"; do
      key_applies_to_ini "$key" "$ini" || continue
      tmp2="$(mktemp)" || { echo "HATA: geçici dosya oluşturulamadı: $ini" >&2; rm -f -- "$filter"; return 1; }
      grep -v -E "$(key_regex "$key")" "$filter" > "$tmp2" || true
      mv -f -- "$tmp2" "$filter"
    done
  fi
  if ((${#MANAGED_INT_KEYS[@]} > 0)); then
    for key in "${MANAGED_INT_KEYS[@]}"; do
      key_applies_to_ini "$key" "$ini" || continue
      tmp2="$(mktemp)" || { echo "HATA: geçici dosya oluşturulamadı: $ini" >&2; rm -f -- "$filter"; return 1; }
      grep -v -E "$(key_regex "$key")" "$filter" > "$tmp2" || true
      mv -f -- "$tmp2" "$filter"
    done
  fi
  if (( MANAGES_FUNCS == 1 )); then
    tmp2="$(mktemp)" || { echo "HATA: geçici dosya oluşturulamadı: $ini" >&2; rm -f -- "$filter"; return 1; }
    grep -v -E "$(key_regex "disable_functions")" "$filter" > "$tmp2" || true
    mv -f -- "$tmp2" "$filter"
  fi

  tmp="$(mktemp "${ini}.tmp.XXXXXX")" || { echo "HATA: geçici dosya oluşturulamadı: $ini" >&2; rm -f -- "$filter"; return 1; }
  {
    printf '; ------------------------------------------------------------------\n'
    printf '; %s v%s -- profil: %s -- %s\n' "$SCRIPT_NAME" "$VERSION" "$PROFILE" "$(date '+%F %T %z')"
    printf '; Bu blok betik tarafindan yonetilir. Onceki icerik su dosyaya yedeklendi:\n'
    printf ';   %s\n' "$backup"
    printf '; Tekrar --apply calistirmak guvenlidir (idempotent).\n'
    for key in "${MANAGED_BOOL_KEYS[@]}"; do
      key_applies_to_ini "$key" "$ini" || continue
      printf '%s = %s\n' "$key" "${EXPECTED_BOOL[$key]}"
    done
    if ((${#MANAGED_SIZE_KEYS[@]} > 0)); then
      for key in "${MANAGED_SIZE_KEYS[@]}"; do
        key_applies_to_ini "$key" "$ini" || continue
        if [[ -n "${KEEP_VALUE[$key]:-}" ]]; then
          printf '%s = %s\n' "$key" "${KEEP_VALUE[$key]}"
        else
          printf '%s = %s\n' "$key" "${CVE_EXPECTED[$key]}"
        fi
      done
    fi
    if ((${#MANAGED_INT_KEYS[@]} > 0)); then
      for key in "${MANAGED_INT_KEYS[@]}"; do
        key_applies_to_ini "$key" "$ini" || continue
        if [[ -n "${KEEP_VALUE[$key]:-}" ]]; then
          printf '%s = %s\n' "$key" "${KEEP_VALUE[$key]}"
        else
          printf '%s = %s\n' "$key" "${CVE_EXPECTED[$key]}"
        fi
      done
    fi
    if (( MANAGES_FUNCS == 1 )); then
      merged="$(merged_disable_csv "$ini")"
      printf 'disable_functions = %s\n' "$merged"
    fi
    printf '\n'
    cat -- "$filter"
  } > "$tmp"
  rm -f -- "$filter"

  # İzin/sahiplik ve desteklenen ACL/xattr üstverisini koru.
  cp --attributes-only --preserve=all -- "$ini" "$tmp" 2>/dev/null || {
    chown --reference="$ini" "$tmp" 2>/dev/null || true
    chmod --reference="$ini" "$tmp" 2>/dev/null || true
  }

  if mv -f -- "$tmp" "$ini"; then
    command -v restorecon >/dev/null 2>&1 && restorecon -F "$ini" >/dev/null 2>&1 || true
    printf 'GÜNCELLENDİ: %s\nYedek: %s\n' "$ini" "$backup"
    return 0
  fi
  echo "HATA: dosya değiştirilemedi: $ini (yedek: $backup)" >&2
  rm -f -- "$tmp"
  return 1
}

do_restore() {
  local ini latest restorable=0 restored=0 failed=0
  local -a cands=() targets=()
  targets=("${INI_FILES[@]}")
  if (( ENFORCE_POOLS == 1 )) && ((${#POOL_FILES[@]} > 0)); then
    targets+=("${POOL_FILES[@]}")
  fi
  for ini in "${targets[@]}"; do
    cands=("${ini}".${BACKUP_SUFFIX}-*)
    if ((${#cands[@]} == 0)); then
      print_warn "$ini: geri yüklenecek yedek bulunamadı (*.${BACKUP_SUFFIX}-*)."
      failed=$((failed+1))
      continue
    fi
    restorable=$((restorable+1))
  done
  if (( restorable == 0 )); then
    print_fail 'Geri yüklenecek yedek bulunamadı.'
    return 1
  fi
  printf '\n%s dosya en yeni yedeğinden geri yüklenecek.\n' "$restorable"
  confirm_or_abort
  for ini in "${targets[@]}"; do
    cands=("${ini}".${BACKUP_SUFFIX}-*)
    if ((${#cands[@]} == 0)); then
      continue
    fi
    latest="$(ls -t -- "${cands[@]}" 2>/dev/null | head -n1)"
    if [[ -z "$latest" || ! -f "$latest" ]]; then
      echo "HATA: yedek okunamadı: $ini" >&2
      failed=$((failed+1))
      continue
    fi
    _tmp="$(mktemp "${ini}.tmp.XXXXXX")" || { echo "HATA: geçici dosya oluşturulamadı: $ini" >&2; failed=$((failed+1)); continue; }
    if ! cat -- "$latest" > "$_tmp"; then
      echo "HATA: yedek kopyalanamadı: $latest" >&2
      rm -f -- "$_tmp"
      failed=$((failed+1))
      continue
    fi
    cp --attributes-only --preserve=all -- "$ini" "$_tmp" 2>/dev/null || {
      chown --reference="$ini" "$_tmp" 2>/dev/null || true
      chmod --reference="$ini" "$_tmp" 2>/dev/null || true
    }
    if mv -f -- "$_tmp" "$ini"; then
      command -v restorecon >/dev/null 2>&1 && restorecon -F "$ini" >/dev/null 2>&1 || true
      printf 'GERİ YÜKLENDİ: %s\nKaynak: %s\n' "$ini" "$latest"
      restored=$((restored+1))
    else
      echo "HATA: dosya geri yüklenemedi: $ini" >&2
      rm -f -- "$_tmp"
      failed=$((failed+1))
    fi
  done
  printf '\nGeri yükleme tamamlandı. Başarılı: %d; hatalı: %d\n' "$restored" "$failed"
  if (( failed > 0 )); then
    return 1
  fi
  return 0
}

# Havuz dosyasına yönetilen bloğu yazar; aynı anahtarların eski aktif
# satırlarını kaldırır (yedek alınır). Idempotent'tir.
apply_pool_file() {
  local pool="$1" stamp="$2"
  local backup tmp tmp2 spec type key value
  backup="${pool}.${BACKUP_SUFFIX}-${stamp}"

  if ! cp -a -- "$pool" "$backup"; then
    echo "HATA: yedek alınamadı: $pool" >&2
    return 1
  fi

  tmp="$(mktemp "${pool}.tmp.XXXXXX")" || { echo "HATA: geçici dosya oluşturulamadı: $pool" >&2; return 1; }
  if ! cp -- "$pool" "$tmp"; then
    echo "HATA: dosya okunamadı: $pool (yedek: $backup)" >&2
    rm -f -- "$tmp"
    return 1
  fi

  # Önceki yönetilen bloğu kaldır.
  tmp2="$(mktemp)" || { echo "HATA: geçici dosya oluşturulamadı: $pool" >&2; rm -f -- "$tmp"; return 1; }
  sed "/^$(printf '%s' "$POOL_BLOCK_BEGIN" | sed 's/[][\\/.*^$]/\\&/g')/,/^$(printf '%s' "$POOL_BLOCK_END" | sed 's/[][\\/.*^$]/\\&/g')/d" "$tmp" > "$tmp2" || true
  mv -f -- "$tmp2" "$tmp"

  # Zorlanan anahtarların tüm aktif satırlarını kaldır (yorumlara dokunma).
  if ((${#POOL_SPECS[@]} > 0)); then
    for spec in "${POOL_SPECS[@]}"; do
      type="${spec%%|*}"
      key="$(printf '%s' "$spec" | cut -d'|' -f2)"
      tmp2="$(mktemp)" || { echo "HATA: geçici dosya oluşturulamadı: $pool" >&2; rm -f -- "$tmp"; return 1; }
      grep -v -E "$(pool_key_regex "$type" "$key")" "$tmp" > "$tmp2" || true
      mv -f -- "$tmp2" "$tmp"
    done
  fi

  # Yönetilen bloğu dosya sonuna ekle.
  {
    printf '\n%s v%s -- %s\n' "$POOL_BLOCK_BEGIN" "$VERSION" "$(date '+%F %T %z')"
    printf '; Bu blok betik tarafindan yonetilir. Onceki icerik su dosyaya yedeklendi:\n'
    printf ';   %s\n' "$backup"
    if ((${#POOL_SPECS[@]} > 0)); then
      for spec in "${POOL_SPECS[@]}"; do
        type="${spec%%|*}"
        key="$(printf '%s' "$spec" | cut -d'|' -f2)"
        value="$(printf '%s' "$spec" | cut -d'|' -f3)"
        pool_spec_line "$type" "$key" "$value"
        printf '\n'
      done
    fi
    printf '%s\n' "$POOL_BLOCK_END"
  } >> "$tmp"

  cp --attributes-only --preserve=all -- "$pool" "$tmp" 2>/dev/null || {
    chown --reference="$pool" "$tmp" 2>/dev/null || true
    chmod --reference="$pool" "$tmp" 2>/dev/null || true
  }

  if mv -f -- "$tmp" "$pool"; then
    command -v restorecon >/dev/null 2>&1 && restorecon -F "$pool" >/dev/null 2>&1 || true
    printf 'GÜNCELLENDİ (havuz): %s\nYedek: %s\n' "$pool" "$backup"
    return 0
  fi
  echo "HATA: dosya değiştirilemedi: $pool (yedek: $backup)" >&2
  rm -f -- "$tmp"
  return 1
}

verify_pool_file() {
  local pool="$1" spec type key value count val failed=0
  if ((${#POOL_SPECS[@]} == 0)); then return 0; fi
  for spec in "${POOL_SPECS[@]}"; do
    type="${spec%%|*}"
    key="$(printf '%s' "$spec" | cut -d'|' -f2)"
    value="$(printf '%s' "$spec" | cut -d'|' -f3)"
    count="$(grep -c -E "$(pool_key_regex "$type" "$key")" "$pool" 2>/dev/null || true)"
    if [[ "$count" != "1" ]]; then
      print_fail "$pool: $key etkin satır sayısı $count (beklenen: 1)."
      failed=1
      continue
    fi
    val="$(grep -E "$(pool_key_regex "$type" "$key")" "$pool" 2>/dev/null | strip_ini_value | head -n1 | trim_spaces)"
    if [[ "$value" == "Off" ]]; then
      if is_off_value "$val"; then
        print_ok "$pool: $key = ${val:-boş} (havuz doğrulandı)"
      else
        print_fail "$pool: $key değeri '${val:-boş}'; $value bekleniyordu."
        failed=1
      fi
    elif [[ "$val" == "$value" ]]; then
      print_ok "$pool: $key = $val (havuz doğrulandı)"
    else
      print_fail "$pool: $key değeri '${val:-boş}'; $value bekleniyordu."
      failed=1
    fi
  done
  return "$failed"
}

describe_pool_state() {
  local pool="$1" spec type key value count val
  if ((${#POOL_SPECS[@]} == 0)); then return 0; fi
  for spec in "${POOL_SPECS[@]}"; do
    type="${spec%%|*}"
    key="$(printf '%s' "$spec" | cut -d'|' -f2)"
    value="$(printf '%s' "$spec" | cut -d'|' -f3)"
    count="$(grep -c -E "$(pool_key_regex "$type" "$key")" "$pool" 2>/dev/null || true)"
    if [[ "$count" == "0" ]]; then
      printf '    %-45s [eklenecek: %s]\n' "$(pool_spec_line "$type" "$key" "$value")" "$value"
    elif [[ "$count" != "1" ]]; then
      printf '    %-45s [DİKKAT: %s etkin satır var; tekilleştirilecek]\n' "$key" "$count"
    else
      val="$(grep -E "$(pool_key_regex "$type" "$key")" "$pool" 2>/dev/null | strip_ini_value | head -n1 | trim_spaces)"
      if [[ "$value" == "Off" ]]; then
        if is_off_value "$val"; then
          printf '    %-45s [zaten %s]\n' "$key" "${val:-boş}"
        else
          printf '    %-45s [değişecek: %s -> %s]\n' "$key" "${val:-boş}" "$value"
        fi
      elif [[ "$val" == "$value" ]]; then
        printf '    %-45s [zaten %s]\n' "$key" "${val:-boş}"
      else
        printf '    %-45s [değişecek: %s -> %s]\n' "$key" "${val:-boş}" "$value"
      fi
    fi
  done
}

# $1: reload | restart — aktif PHP-FPM + Apache servislerine uygular.
service_action() {
  local action="$1"
  local -a units=()
  local ok=0 failed=0 skipped=0
  printf '\nServis %s (%s):\n' "$action" "--$action"
  if ! command -v systemctl >/dev/null 2>&1; then
    print_warn "systemctl bulunamadı; servisleri elle $action edin (aşağıdaki nota bakın)."
    return 0
  fi
  mapfile -t units < <(systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}' | grep -Ei '(php|ea-|plesk|alt-).*fpm|fpm.*(php|ea-|plesk)|^(httpd|apache2)\.service$' || true)
  if ((${#units[@]} == 0)); then
    print_info "$action edilecek PHP-FPM/Apache servisi bulunamadı; gerekirse elle işlem yapın."
  else
    for _u in "${units[@]}"; do
      if ! systemctl is-active --quiet "$_u" 2>/dev/null; then
        skipped=$((skipped+1))
        continue
      fi
      if systemctl "$action" "$_u" 2>/dev/null; then
        print_ok "$action: $_u"
        ok=$((ok+1))
      else
        print_warn "$action başarısız: $_u (elle 'systemctl $action $_u' deneyin)"
        failed=$((failed+1))
      fi
    done
    printf '%s özeti: başarılı=%d, atlanan (pasif)=%d, hatalı=%d\n' "$action" "$ok" "$skipped" "$failed"
  fi
  if systemctl list-unit-files --type=service --no-legend 2>/dev/null | grep -Eqi '^(lsws|openlitespeed|lshttpd)\.service'; then
    print_warn "LiteSpeed tespit edildi: PHP'nin yeni ayarı okuması için LiteSpeed'i panelden graceful restart edin (betik LiteSpeed'e dokunmaz)."
  fi
  if (( failed > 0 )); then
    return 1
  fi
  return 0
}

print_final_notes() {
  cat <<'NOTE'

ÖNEMLİ:
- PHP-FPM kullanan sistemlerde değişikliğin web isteklerine yansıması için ilgili
  servislerin reload/restart edilmesi gerekir (--reload/--restart bunu dener).
  mod_php için Apache restart, LiteSpeed için panelden graceful restart gerekir.
- Bu ayarlar PHP_INI_PERDIR kapsamındadır: .user.ini, vhost veya PHP-FPM havuz
  ayarları değeri tekrar açabilir. Havuz taraması yukarıda raporlanır; web
  tarafında ayrıca doğrulayın.
- disable_functions mevcut değerlerle BİRLEŞTİRİLİR; panelinizin varsayılan
  kapalı listesi korunur, üzerine profil listesi eklenir.
- Bu betik geçici bir azaltımdır (mitigation); PHP/vendor güvenlik yamalarının
  yerine geçmez. Yamalı sürüme (8.2.35+/8.3.36+/8.4.27+/8.5.12+) güncelleyin.
NOTE
}

print_cve_notes() {
  cat <<'NOTE'

CVE-2026-109618/109619 NOTLARI:
- Bu azaltımlar KISMİ koruma sağlar; yamalı PHP'ye güncellemek tek tam çözümdür.
  Yama yapamıyorsanız internete açık siteleri geçici olarak kapatmayı değerlendirin.
- Değişiklik sonrası TÜM PHP worker'ların yeniden başlaması gerekir (--restart
  önerilir). FPM'de reload da worker'ları yeniler; mod_php'de Apache restart şart.
- memory_limit=-1 kullandıysanız cgroup/container limitiyle sınırlandırın ve
  yama sonrası gerçek limite dönün. RLIMIT_AS/RLIMIT_DATA (Apache RLimitMEM)
  kullanmayın; açığı tetikleyebilir.
- pm.max_requests=1 kullandıysanız yama sonrası eski değere dönün (performans).
- Duyurular: https://www.php.net/index.php#2026-10-21-5
NOTE
}

# ---------------------------------------------------------------------------
# Modlar
# ---------------------------------------------------------------------------
if [[ "$MODE" == 'dry-run' ]]; then
  scan_fpm_pools
  if (( ENFORCE_POOLS == 1 )); then
    printf '\nHavuz zorlama planı (%d dosya):\n' "${#POOL_FILES[@]}"
    if ((${#POOL_FILES[@]} == 0)); then
      print_warn "Zorlanacak havuz dosyası bulunamadı (--pool-conf ile ekleyebilirsiniz)."
    else
      for _pool in "${POOL_FILES[@]}"; do
        printf '  %s\n' "$_pool"
        describe_pool_state "$_pool"
      done
    fi
  fi
  _cve_flags=""
  if (( CVE_MITIGATE == 1 )); then _cve_flags=" --cve-mitigate"; fi
  if (( ENFORCE_POOLS == 1 )); then _cve_flags="$_cve_flags --enforce-pools"; fi
  cat <<NOTE

DRY-RUN: Hiçbir dosya değiştirilmedi. [profil: $PROFILE]
Uygulamak için:
  bash $SCRIPT_NAME --apply --profile $PROFILE$_cve_flags
Yalnızca doğrulama yapmak için:
  bash $SCRIPT_NAME --check --profile $PROFILE$_cve_flags
NOTE
  if (( CVE_MITIGATE == 1 || ENFORCE_POOLS == 1 )); then print_cve_notes; fi
  exit 0
fi

if [[ "$MODE" == 'check' ]]; then
  printf '\nCHECK: Hiçbir dosya değiştirilmeyecek; mevcut durum doğrulanıyor.\n'
  verification_failed=0
  for _ini in "${INI_FILES[@]}"; do
    verify_ini_file "$_ini" || verification_failed=1
  done
  verify_php_cli_settings || verification_failed=1
  if (( ENFORCE_POOLS == 1 )); then
    printf '\nHavuz zorlama doğrulaması:\n'
    if ((${#POOL_FILES[@]} == 0)); then
      print_fail "Doğrulanacak havuz dosyası bulunamadı."
      verification_failed=1
    else
      for _pool in "${POOL_FILES[@]}"; do
        verify_pool_file "$_pool" || verification_failed=1
      done
    fi
  fi
  scan_fpm_pools
  if (( CVE_MITIGATE == 1 || ENFORCE_POOLS == 1 )); then print_cve_notes; fi
  if (( verification_failed > 0 )); then
    printf '\nCHECK SONUCU: BAŞARISIZ -- yukarıdaki [FAIL] satırlarını inceleyin.\n'
    exit 1
  fi
  printf '\nCHECK SONUCU: BAŞARILI -- bulunan INI dosyaları ve PHP CLI ayarları doğrulandı.\n'
  exit 0
fi

if [[ "$MODE" == 'restore' ]]; then
  printf '\nRESTORE: INI dosyaları en yeni yedeklerinden geri yüklenecek.\n'
  restore_failed=0
  do_restore || restore_failed=1
  printf '\nGeri yükleme sonrası dosya doğrulaması (--check profilinizi ayrıca çalıştırın):\n'
  for _ini in "${INI_FILES[@]}"; do
    if grep -Eq "$(key_regex "session.upload_progress.enabled")" "$_ini" 2>/dev/null; then
      print_info "$_ini: session.upload_progress.enabled satırı mevcut."
    else
      print_warn "$_ini: session.upload_progress.enabled satırı yok (yedek öncesi duruma dönülmüş olabilir)."
    fi
  done
  if (( restore_failed > 0 )); then
    exit 1
  fi
  exit 0
fi

# --apply
printf '\nAPPLY: %d INI dosyası güncellenecek [profil: %s].\n' "${#INI_FILES[@]}" "$PROFILE"
_pool_count=0
if (( ENFORCE_POOLS == 1 )); then
  _pool_count="${#POOL_FILES[@]}"
  printf 'APPLY: %d havuz dosyası güncellenecek.\n' "$_pool_count"
  if (( _pool_count == 0 )); then
    print_warn "Havuz dosyası bulunamadı; yalnızca INI dosyaları işlenecek."
  fi
fi
if (( RESTART == 1 )); then
  print_warn "--restart verildi: PHP-FPM + Apache servisleri yeniden başlatılacak (kısa kesinti olur)."
fi
confirm_or_abort
stamp="$(date +%Y%m%d-%H%M%S)"
changed=0
failed=0
for _ini in "${INI_FILES[@]}"; do
  if apply_file "$_ini" "$stamp"; then
    changed=$((changed+1))
  else
    failed=$((failed+1))
  fi
done
pool_changed=0
if (( ENFORCE_POOLS == 1 )) && ((${#POOL_FILES[@]} > 0)); then
  for _pool in "${POOL_FILES[@]}"; do
    if apply_pool_file "$_pool" "$stamp"; then
      pool_changed=$((pool_changed+1))
    else
      failed=$((failed+1))
    fi
  done
fi

printf '\nDosya içeriği doğrulaması:\n'
verification_failed=0
for _ini in "${INI_FILES[@]}"; do
  verify_ini_file "$_ini" || verification_failed=1
done
if (( ENFORCE_POOLS == 1 )) && ((${#POOL_FILES[@]} > 0)); then
  printf '\nHavuz içeriği doğrulaması:\n'
  for _pool in "${POOL_FILES[@]}"; do
    verify_pool_file "$_pool" || verification_failed=1
  done
fi

verify_php_cli_settings || verification_failed=1
scan_fpm_pools

service_failed=0
if (( RESTART == 1 )); then
  service_action "restart" || service_failed=1
elif (( RELOAD == 1 )); then
  service_action "reload" || service_failed=1
fi

printf '\nTamamlandı. Güncellenen INI: %d; güncellenen havuz: %d; dosya işlemi hatası: %d; doğrulama hatası: %d; servis hatası: %d\n' \
  "$changed" "$pool_changed" "$failed" "$verification_failed" "$service_failed"
print_final_notes
if (( CVE_MITIGATE == 1 || ENFORCE_POOLS == 1 )); then print_cve_notes; fi

if (( failed > 0 || verification_failed > 0 || service_failed > 0 )); then
  exit 1
fi
exit 0
