# disable-session-upload-progress

PHP sunucularda `session.upload_progress` istismar yüzeyini kapatan ve `php.ini`
sertleştirmesi uygulayan Bash betiği. cPanel/WHM, DirectAdmin ve Plesk dahil tüm
yaygın hosting panellerini ve PHP kurulumlarını otomatik tespit eder.

> **English summary:** A Bash hardening script that disables PHP
> `session.upload_progress` (LFI-to-RCE chain mitigation) in every global
> `php.ini`, with optional `disable_functions` and security-directive profiles.
> Auto-detects cPanel/WHM, DirectAdmin, Plesk, CloudLinux alt-php and generic
> Linux PHP installs. Default mode is dry-run; `--apply` writes timestamped
> backups. See [Hızlı başlangıç](#hızlı-başlangıç) below.

## İçindekiler

- [Bu betik ne yapar?](#bu-betik-ne-yapar)
- [Neden gerekli? (Tehdit modeli)](#neden-gerekli-tehdit-modeli)
- [CVE-2026-109618 / CVE-2026-109619 geçici düzeltmesi](#cve-2026-109618--cve-2026-109619-geçici-düzeltmesi)
- [Desteklenen sistemler](#desteklenen-sistemler)
- [Profiller](#profiller)
- [Hızlı başlangıç](#hızlı-başlangıç)
- [Komut satırı seçenekleri](#komut-satırı-seçenekleri)
- [Örnek çıktı](#örnek-çıktı)
- [Doğrulama](#doğrulama)
- [Geri alma (restore)](#geri-alma-restore)
- [Servis reload notu](#servis-reload-notu)
- [SSS](#sss)
- [Güvenlik notları ve sınırlamalar](#güvenlik-notları-ve-sınırlamalar)
- [Dosyalar](#dosyalar)

## Bu betik ne yapar?

1. Sunucudaki paneli tespit eder (cPanel/WHM, DirectAdmin, Plesk veya genel Linux).
2. Tüm PHP CLI binary'lerini ve bunların kullandığı `php.ini` dosyalarını bulur;
   CLI sunmayan kurulumlar için bilinen `php.ini` yollarını da tarar.
3. Seçilen profile göre yönetilen direktifleri **dosyanın en üstüne, global kapsama**
   tekil satırlar olarak yazar; aynı direktifin yinelenen aktif satırlarını temizler.
4. `disable_functions` değerini **mevcut değerle birleştirir** — panelin varsayılan
   kapalı listesi silinmez, üzerine profil listesi eklenir.
5. Her değişen dosyanın zaman damgalı yedeğini alır
   (`php.ini.bak.session-upload-progress-YYYYMMDD-HHMMSS`).
6. İşlem sonrası dosya içeriğini ve `php -i` etkin değerlerini doğrular; ayrıca
   ayarı tekrar açan PHP-FPM havuz dosyalarını raporlar.

Varsayılan mod **dry-run**'dır: hiçbir dosya değiştirilmez, yalnızca tespit ve
plan listelenir.

## Neden gerekli? (Tehdit modeli)

PHP'nin `session.upload_progress` özelliği açıkken, dosya yükleyen bir POST
isteğine `PHP_SESSION_UPLOAD_PROGRESS` alanı eklenerek oturum (session)
dosyasına saldırgan kontrollü veri yazdırılabilir. Uygulamadaki bir LFI
(Local File Inclusion) zafiyetiyle birleştiğinde bu mekanizma, oturum dosyası
üzerinden kod çalıştırma (RCE) zincirinin parçası olarak istismar edilir.

Betik, tüm global `php.ini` dosyalarında bu özelliği kapatarak istismar
yüzeyini daraltır:

```ini
session.upload_progress.enabled = Off
session.upload_progress.cleanup = On
```

Bu, **geçici bir azaltımdır (mitigation)**; PHP ve uygulama güvenlik
yamalarının yerine geçmez. Yamalar çıktıkça uygulanmalıdır.

## CVE-2026-109618 / CVE-2026-109619 geçici düzeltmesi

21 Ekim 2026'da duyurulan iki kritik açık ("php2shell"), kimlik doğrulamasız
uzaktan kod çalıştırmaya izin veriyor. Web isteği sunan tüm PHP kurulumları
etkilenir (PHP-FPM, mod_php, php-cgi, LiteSpeed, FrankenPHP); PHP ekibi riski
`mod_php` için en yüksek olarak değerlendiriyor.

| CVE | Mekanizma | Doğrulanan tetik yolları |
|---|---|---|
| CVE-2026-109618 | OOM sırasında bozuk istek temizliği (RCE) | multipart istek ayrıştırma |
| CVE-2026-109619 | Serbest bırakılmış eski global state kullanımı (RCE) | session upload-progress; PHP 8.5'te fatal backtrace |

### Etkilenen ve yamalı sürümler (PHP 5 / 7 / 8)

| Sürüm aralığı | Durum |
|---|---|
| PHP 5.4 – 8.1 (5.4.0'dan itibaren `session.upload_progress` içeren tüm sürümler) | **Etkilenir, resmi yama yok** (EOL). Dağıtım/LTS vendor yamasını kontrol edin; 7.4/8.0/8.1 için PHP ekibinin minimal kaynak yamaları mevcut. |
| PHP 8.2.0 – 8.2.34 | Etkilenir → **8.2.35**'e güncelleyin |
| PHP 8.3.0 – 8.3.35 | Etkilenir → **8.3.36**'ya güncelleyin |
| PHP 8.4.0 – 8.4.26 | Etkilenir → **8.4.27**'ye güncelleyin |
| PHP 8.5.0 – 8.5.11 | Etkilenir → **8.5.12**'ye güncelleyin |
| PHP 5.3 ve öncesi | `session.upload_progress` içermez; ancak desteksizdir, yükseltin |

Öncelik sırası: **1)** yamalı PHP'ye güncelleyin (panelinizin PHP derlemelerini:
cPanel EA4, CloudLinux alt-php, DirectAdmin CustomBuild, Plesk güncellemelerini
takip edin), **2)** güncelleyene kadar aşağıdaki geçici düzeltmeyi uygulayın.
Azaltımlar kısmi koruma sağlar; yama yapamıyorsanız internete açık siteleri
geçici olarak kapatmayı değerlendirin.

### Betiğin uyguladığı geçici düzeltme

`--cve-mitigate` bayrağı, seçilen profile ek bir katman olarak resmi duyurudaki
PHP-tarafı önlemleri uygular. Sürüme duyarlıdır: her `php.ini` için sürüm
tespit edilir (önce PHP binary'sinden, yoksa dosya yolundaki ipucundan) ve
desteklenmeyen direktifler atlanır.

| Önlem | PHP 5.4–8.x | PHP 8.5+ | Not |
|---|---|---|---|
| `session.upload_progress.enabled = Off` | Evet | Evet | 109619'un doğrulanan session yolu |
| `post_max_size` sıkılaştırma (varsayılan 32M) | Evet | Evet | Yüklemesiz sitelerde `--post-max-size 8M`; mevcut katı değer korunur, asla gevşetilmez |
| `upload_max_filesize` (varsayılan post−1M) | Evet | Evet | Her zaman `post_max_size` altında tutulur |
| `max_input_vars` (1000), `max_input_nesting_level` (64), `max_file_uploads` (20) | Evet | Evet | Yalnızca gevşek değerler hedefe çekilir |
| `fatal_error_backtraces = 0` | Atlanır | Evet | Yalnızca 8.5+'ta mevcut; eski sürüme yazılmaz |
| `max_multipart_body_parts`, `memory_limit` | Bilgi satırı | Bilgi satırı | Betik ini içinde değiştirmez; havuz bayraklarına bakın |

`--enforce-pools` ile FPM havuzlarına `php_admin_value` zorlaması yazılır
(uygulamanın `.user.ini`/`ini_set` ile ezemeyeceği şekilde):

```ini
php_admin_value[session.upload_progress.enabled] = Off
```

İsteğe bağlı, riskli ama etkili iki havuz bayrağı daha vardır:

- `--pool-memory-unlimited` → `php_admin_value[memory_limit] = -1`
  (109618'in ana azaltması). **Uyarı:** cgroup/container limiti olmadan tek
  istek tüm RAM'i tüketebilir. CloudLinux LVE/containersız paylaşımlı
  sunucularda dikkatli kullanın; yama sonrası gerçek limite dönün.
- `--pool-max-requests-1` → `pm.max_requests = 1` (her worker tek istek
  işler, 109619'un istekler-arası state yolunu keser). **Uyarı:** ciddi
  performans kaybı olur; yama sonrası eski değere dönün.

```bash
# Önerilen geçici düzeltme komutu (önce dry-run ile inceleyin)
sudo bash disable-session-upload-progress.sh --cve-mitigate --enforce-pools
sudo bash disable-session-upload-progress.sh --apply --profile standard \
  --cve-mitigate --post-max-size 8M --enforce-pools --restart --yes
```

Değişiklik sonrası **tüm worker'ların yeniden başlaması gerekir** (`--restart`
önerilir; FPM'de reload da worker'ları yeniler, mod_php'de Apache restart şart).

### İşe yaramadığı doğrulananlar (uygulamayın)

Resmi duyuru ve sonrası analizlere göre şu önlemler bu açıklara karşı koruma
**sağlamaz**: `file_uploads = Off` (multipart gövde yine ayrıştırılır),
`display_errors`/`error_reporting`/`@` ile hata gizleme, `ini_set()`/`.user.ini`
ile azaltma (isteğe çok geç uygulanır), uygulama katmanı kontrolleri (saldırı
kodunuz çalışmadan önce olur), `RLIMIT_AS`/`RLIMIT_DATA` bellek limiti (açığı
tetikler), `session.use_strict_mode`, WAF arkasına alıp sunucuyu doğrudan
erişilebilir bırakma. `enable_post_data_reading = Off` ve
`max_multipart_body_parts` için doğrulanmış güvenli değer yoktur; bu yüzden
betik bunları zorlamaz.

Tamamlayıcı olarak web sunucusu/CDN katmanında multipart istekleri
kısıtlamayı (yükleme uçları dışına multipart yasağı; `Content-Length` içermeyen
istekler dahil) ve saldırı izlerini (FPM segfault, anormal multipart trafiği)
izlemeyi değerlendirin.

Kaynaklar: [PHP güvenlik duyurusu](https://www.php.net/index.php#2026-10-21-5),
[CVE-2026-109618 (GHSA-w8hw-w9fx-j79w)](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w),
[CVE-2026-109619 (GHSA-6wmf-4rv5-p3rp)](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp),
[erken azaltım rehberi (ma.ttias.be)](https://ma.ttias.be/php-cve-2026-109618-early-mitigation/).

## Desteklenen sistemler

| Ortam | Tespit yöntemi | Kapsanan PHP yolları |
|---|---|---|
| cPanel/WHM (EasyApache 4) | `/usr/local/cpanel` | `/opt/cpanel/ea-php*/root/etc/php.ini`, `/usr/local/bin/ea-php*` |
| CloudLinux alt-php (PHP Selector) | alt-php yolları | `/opt/alt/php*/etc/php.ini`, `/opt/alt/php*/usr/bin/php` |
| DirectAdmin (CustomBuild) | `/usr/local/directadmin` | `/usr/local/php*/lib/php.ini`, `/usr/local/php*/bin/php`, kullanıcı `php/*.ini` |
| Plesk | `/usr/local/psa`, `plesk` binary | `/opt/plesk/php/*/etc/php.ini`, `/opt/plesk/php/*/bin/php`, `/var/www/vhosts/system/*/etc/php.ini` |
| Genel Linux (deb/rpm) | — | `/etc/php.ini`, `/etc/php/*/fpm|apache2|cli|cgi/php.ini`, `/usr/bin/php*` |

Tespit edilemeyen özel kurulumlar `--ini` ve `--php-bin` seçenekleriyle eklenebilir.

## Profiller

| Direktif | `minimal` | `standard` (varsayılan) | `strict` |
|---|---|---|---|
| `session.upload_progress.enabled` | `Off` | `Off` | `Off` |
| `session.upload_progress.cleanup` | — | `On` | `On` |
| `expose_php` | — | `Off` | `Off` |
| `allow_url_include` | — | `Off` | `Off` |
| `display_errors` | — | — | `Off` |
| `log_errors` | — | — | `On` |
| `disable_functions` | yönetilmez | standart liste | standart + geniş liste |

- **minimal:** Yalnızca upload-progress azaltımı. v1 betiğiyle aynı davranıştır;
  mevcut uygulamalara etkisi pratikte yoktur.
- **standard:** Paylaşımlı hosting için önerilen denge. Tehlikeli kabuk/işlem
  fonksiyonlarını kapatır; tipik CMS ve framework uygulamaları etkilenmez.
- **strict:** Yüksek güvenlik istenen sunucular için. Ek fonksiyonlar ve hata
  çıktısı kısıtlaması içerir; devreye almadan önce uygulamanızı test edin.

**Standard `disable_functions` listesi:**

```ini
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec,show_source
```

**Strict listeye ek olarak** (alfabetik): `apache_child_terminate`,
`apache_setenv`, `define_syslog_variables`, `expect_popen`, `link`, `posix_kill`,
`posix_mkfifo`, `posix_setgid`, `posix_setpgid`, `posix_setsid`, `posix_setuid`,
`posix_uname`, `proc_close`, `proc_get_status`, `proc_nice`, `proc_terminate`,
`symlink` ve `pcntl_*` fonksiyon ailesinin tamamına yakını
(`pcntl_fork`, `pcntl_signal`, `pcntl_signal_dispatch`, `pcntl_sigprocmask`,
`pcntl_sigwaitinfo`, `pcntl_sigtimedwait`, `pcntl_alarm`, `pcntl_waitpid`,
`pcntl_wexitstatus`, `pcntl_wifexited`, `pcntl_wifstopped`, `pcntl_wifsignaled`,
`pcntl_wtermsig`, `pcntl_wstopsig`, `pcntl_get_last_error`, `pcntl_strerror`,
`pcntl_async_signals`).

`disable_functions` her zaman **birleştirilerek** yazılır: dosyadaki mevcut
liste korunur, eksik olan profil fonksiyonları başa eklenir.

## Hızlı başlangıç

```bash
# 1. Betiği sunucuya kopyalayın ve çalıştırılabilir yapın
chmod +x disable-session-upload-progress.sh

# 2. Önce dry-run ile neyin değişeceğini görün (değişiklik yapmaz, root gerekmez)
bash disable-session-upload-progress.sh --profile standard

# 3. Uygulayın (root gerekir, yedek alınır, onay sorulur)
sudo bash disable-session-upload-progress.sh --apply --profile standard

# 4. Uygulama + PHP-FPM reload'u tek komutta (onaysız)
sudo bash disable-session-upload-progress.sh --apply --profile standard --reload --yes

# 5. Daha sonra durumu doğrulayın (değişiklik yapmaz)
sudo bash disable-session-upload-progress.sh --check --profile standard

# 6. CVE-2026-109618/109619 geçici düzeltmesi (önce dry-run ile inceleyin)
bash disable-session-upload-progress.sh --cve-mitigate --enforce-pools
sudo bash disable-session-upload-progress.sh --apply --profile standard \
  --cve-mitigate --post-max-size 8M --enforce-pools --restart --yes
```

v1 davranışını (yalnızca upload-progress kapatma) isteyenler:

```bash
sudo bash disable-session-upload-progress.sh --apply --profile minimal
```

## Komut satırı seçenekleri

| Seçenek | Açıklama |
|---|---|
| `--dry-run` | Tespit + plan listeler; değişiklik yapmaz (varsayılan, root gerekmez). |
| `--apply` | Yedek alıp INI dosyalarını günceller ve doğrular (root gerekir). |
| `--check` | Dosya değiştirmeden INI içeriklerini ve `php -i` değerlerini doğrular. |
| `--restore` | Her INI dosyasını en yeni `.bak.session-upload-progress-*` yedeğine döndürür. |
| `--profile minimal\|standard\|strict` | Sertleştirme profili (varsayılan: `standard`). |
| `--cve-mitigate` | CVE katmanı: boyut + girdi limitleri, 8.5+ için `fatal_error_backtraces=0`. |
| `--post-max-size BOYUT` | Hedef `post_max_size` (varsayılan: `32M`). |
| `--upload-max-filesize BOYUT` | Hedef `upload_max_filesize` (varsayılan: post−1M). |
| `--enforce-pools` | FPM havuzlarına `php_admin_value` zorlaması yazar. |
| `--pool-conf YOL` | Keşfe ek FPM havuz dosyası ekler (tekrarlanabilir). |
| `--pool-memory-unlimited` | Havuzlara `memory_limit=-1` ekler (cgroup şart, riskli). |
| `--pool-max-requests-1` | Havuzlara `pm.max_requests=1` ekler (performans kaybı). |
| `--reload` | `--apply` sonrası FPM servislerine reload + Apache'ye graceful reload yapar. |
| `--restart` | `--apply` sonrası FPM + Apache servislerini yeniden başlatır. |
| `--yes, -y` | Onay sorusunu atlar (otomasyon için). |
| `--ini YOL` | Keşfe ek `php.ini` dosyası ekler (tekrarlanabilir). |
| `--php-bin YOL` | Keşfe ek PHP CLI binary ekler (tekrarlanabilir). |
| `--no-color` | Renkli çıktıyı kapatır (`NO_COLOR` ortam değişkeni de geçerlidir). |
| `--version` | Sürümü yazdırır. |
| `-h, --help` | Yardımı yazdırır. |

Çıkış kodları: `0` başarılı, `1` doğrulama/uygulama hatası, `2` kullanım hatası.

## Örnek çıktı

```text
Panel tespiti: cPanel/WHM
Betik: disable-session-upload-progress.sh v2.1.0 | Mod: dry-run | Profil: standard | CVE-2026-109618/109619 azaltma: kapalı

Bulunan PHP CLI sürümleri:
  PHP 8.1.27     binary=/opt/cpanel/ea-php81/root/usr/bin/php
    ini=/opt/cpanel/ea-php81/root/etc/php.ini
  PHP 8.2.18     binary=/opt/cpanel/ea-php82/root/usr/bin/php
    ini=/opt/cpanel/ea-php82/root/etc/php.ini

Bulunan PHP yapılandırma dosyaları (2) [profil: standard]:
  /opt/cpanel/ea-php81/root/etc/php.ini
    session.upload_progress.enabled     [ayar yok; eklenecek (Off)]
    session.upload_progress.cleanup     [ayar yok; eklenecek (On)]
    expose_php                          [değişecek: On -> Off]
    allow_url_include                   [zaten Off]
    disable_functions                   [birleştirilecek (eksik: pcntl_exec,show_source)]

PHP-FPM havuz override taraması:
[OK] upload-progress'i tekrar açan PHP-FPM havuz ayarı bulunamadı.

DRY-RUN: Hiçbir dosya değiştirilmedi. [profil: standard]
```

## Doğrulama

Betik iki katmanlı doğrulama yapar:

1. **Dosya doğrulaması:** Her INI dosyasında yönetilen direktiflerin tam bir
   aktif satırla ve beklenen değerle yazıldığı; `disable_functions` satırının
   profil listesindeki tüm fonksiyonları içerdiği kontrol edilir.
2. **PHP CLI doğrulaması:** Bulunan her gerçek PHP CLI binary için `php -i`
   çıktısında `directive => Local => Master` değerleri kontrol edilir.

Sınırlama: CLI doğrulaması, PHP-FPM/LiteSpeed ile sunulan web isteklerinin
etkin değerini kanıtlamaz. Web tarafını ayrıca doğrulayın — örneğin geçici bir
`phpinfo()` sayfasıyla `session.upload_progress.enabled` değerine bakıp sayfayı
hemen silin. `.user.ini`, vhost ve FPM havuz ayarları global `php.ini` değerini
ezebilir; havuz taraması betik çıktısında raporlanır.

## Geri alma (restore)

```bash
sudo bash disable-session-upload-progress.sh --restore
```

Her dosya, yanındaki en yeni `.bak.session-upload-progress-*` yedeğinden geri
yüklenir (izin/sahiplik korunur). Belirli bir dosyayı elle döndürmek için:

```bash
cp -a /opt/cpanel/ea-php81/root/etc/php.ini.bak.session-upload-progress-20260101-120000 \
      /opt/cpanel/ea-php81/root/etc/php.ini
systemctl reload ea-php81-php-fpm
```

## Servis reload notu

Betik varsayılan olarak **hiçbir servisi yeniden başlatmaz**. PHP-FPM
kullanıyorsanız değişikliğin web'e yansıması için reload gerekir:

```bash
sudo bash disable-session-upload-progress.sh --apply --reload
```

`--reload` yalnızca aktif PHP-FPM servislerine `systemctl reload` dener;
başarısız olanlar raporda `[UYARI]` ile gösterilir. Apache/Nginx/LiteSpeed için
gerekirse ayrıca graceful reload yapın (ör. `apachectl graceful`,
`nginx -s reload` veya panelin graceful restart düğmesi).

## SSS

**Sitem bozulur mu?**

- `minimal` profili yalnızca upload-progress izlemeyi kapatır; dosya yükleme
  özelliğinin kendisi çalışmaya devam eder, yalnızca ilerleme yüzdesi API'si
  (`session.upload_progress.*` okuyan sayaçlar) veri döndürmez.
- `standard` profildeki fonksiyonlar (exec, system, …) tipik WordPress/Joomla/
  Laravel uygulamalarında kullanılmaz; ancak yedekleme, PDF üretimi veya harici
  komut çalıştıran eklentileriniz varsa önce test ortamında doğrulayın.
- `strict` profili `symlink`, `display_errors` gibi ek kısıtlar içerir; canlıya
  almadan önce mutlaka test edin.

**`allow_url_fopen` neden kapatılmıyor?**

`allow_url_fopen = Off`, WordPress güncellemeleri, Composer ve birçok
kütüphaneyi bozar. `allow_url_include = Off` (betiğin kapattığı ayar), uzaktan
kod dahil etme riskini tek başına ortadan kaldırır; `allow_url_fopen` bilerek
listeye alınmamıştır.

**`phpinfo` neden `disable_functions` listesinde yok?**

`phpinfo()` bilgi sızıntısı yaratabilir ama uzaktan kod çalıştırma sağlamaz;
kapatılması sorun gidermeyi zorlaştırır. Gerekirse panelinizden veya ek bir
`--ini` katmanından kendiniz ekleyebilirsiniz.

**CloudLinux PHP Selector kullanıyorum, ne olur?**

`/opt/alt/php*` yolları keşfe dahildir; tüm alt-php sürümlerinin `php.ini`
dosyaları güncellenir. Kullanıcıların Selector üzerinden yaptığı özel seçimler
(`disable_functions` dahil) birleştirme mantığı sayesinde korunur.

**`.user.ini` dosyaları güncelleniyor mu?**

Hayır. Betik yalnızca global `php.ini` dosyalarını yönetir; hesap düzeyindeki
`.user.ini` ve vhost override'ları bilerek değiştirilmez. `--check` çıktısı ve
FPM havuz taramasıyla bu istisnaları tespit edip elle kapatın.

**Betik tekrar çalıştırılabilir mi?**

Evet, `--apply` idempotent'tir: ikinci çalıştırmada zaten doğru olan satırlar
aynen korunur, yeni yedek yalnızca içerik değişirse anlamlıdır (yedek her
çalışmada alınır, dosya yalnızca blok yeniden yazılarak güncellenir).

**Root yetkisi şart mı?**

`--dry-run` ve `--check` root'suz çalışır (okunamayan dosyalar atlanır).
`--apply`, `--restore` ve `--reload` root gerektirir.

## Güvenlik notları ve sınırlamalar

- Betik geçici bir azaltımdır; PHP/vendor yamalarının yerine geçmez.
- `session.upload_progress.*` direktifleri `PHP_INI_PERDIR` kapsamındadır:
  `.user.ini`, `php_admin_value`/`php_value` ve havuz ayarları global değeri
  ezebilir. `--check` + havuz taraması + web tarafı doğrulama birlikte kullanılmalıdır.
- Betik bash 4+ gerektirir (RHEL 7+, tüm güncel Debian/Ubuntu, CloudLinux).
- Yedek dosyaları (`*.bak.session-upload-progress-*`) web kök dizini altında
  değil, INI dosyalarının yanında tutulur; yedekleri düzenli aralıklarla
  temizleyin veya merkezi yedeklemenize dahil edin.
- Bu betiği çalıştırmadan önce snapshot/imalar gibi sunucu düzeyinde yedeğinizin
  olduğunu doğrulayın.

## Dosyalar

| Dosya | Açıklama |
|---|---|
| `disable-session-upload-progress.sh` | Ana betik (v2.1). |
| `README.md` | Bu belge. |

Katkı ve hata bildirimi için lütfen GitHub üzerinden issue/PR açın; PR'lerinizde
hangi panel ve PHP sürümlerinde test ettiğinizi belirtin.
