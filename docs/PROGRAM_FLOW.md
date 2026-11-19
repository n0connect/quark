# Quark — Baştan Sona Program Akışı

Bu doküman, müşteri bilgisayarında `DRM_Wrapper.exe` çalıştırıldığı andan
itibaren, `quark.jar` gerçek uygulamayı (`main.jar`) başlatana kadar olan
**tüm zinciri**, tek tek ve sırasıyla anlatır. Her adım kendinden önceki adımın
ürettiği bir değeri kullanır -- yani zincirin herhangi bir halkası eksik veya
yanlışsa, sonraki halka da kendiliğinden yanlış (ve geri döndürülemez şekilde
işe yaramaz) olur. Daha önce dağıtılmış iki belge bu akışın "neden böyle"
sorusuna cevap verir: mimari kurallar için [`CLAUDE.md`](../CLAUDE.md), C++↔Java
köprüsünün protokol detayları için [`HANDOFF_PROTOCOL.md`](HANDOFF_PROTOCOL.md).
Burada amaç farklı: sadece **akışın kendisini**, baştan sona, tek cümlelik
adımlarla, hiçbir boşluk bırakmadan anlatmak.

---

## Hazırlık aşaması (geliştirici tarafında, bir kere yapılır)

1. Geliştirici, `cpp/drm_wrapper/secret.hpp` içine yüksek-entropili, derleme
   zamanına gömülü bir `SECRET` sabiti yazar; bu sabit hiçbir zaman dosyaya,
   ağa veya loglara çıkmaz, sadece ikili dosyanın içine gömülür.
2. `Dev_Keygen.exe`, hedef müşteri makinesinin `hwid.json` dosyasını (HWID_Extractor
   ile toplanmış 11 alanlık parmak izi) ve `SECRET`'i girdi olarak alır.
3. `Dev_Keygen.exe`, rastgele bir `seed (x)` seçer ve `H^0(x)=SHA256(x)`'ten
   başlayarak `H^n(x)`'e kadar bir Lamport zinciri (`n` = izin verilen kullanım
   sayısı) hesaplar.
4. Zincirin en son halkası olan `H^n(x)` ("anchor"), `state.bin` dosyasının
   içine -- müşterinin HWID'i AAD olarak kullanılarak AES-256-GCM ile
   mühürlenmiş şekilde -- yazılır.
4a. `Dev_Keygen.exe`, geliştiricinin `app.bundle` dosyasını (quark-protect + quark-build
    tarafından oluşturulmuş) alarak `core_enc_key = SHA256("QUARK-CORE-ENC-KEY" ||
    state_key || SHA256(online_secret) || hwid_canonical)` anahtarıyla AES-256-GCM
    ile şifreler ve `core.enc` olarak yazar. Bu anahtar her oturumda değişmeyen,
    müşteriye özgü kararlı (stable) bir anahtar olduğundan `core.enc` lisans ömrü
    boyunca aynı kalır.
4b. Müşteriye teslim edilen paket: `state.bin` + `core.enc` + `unlock_keys.txt` +
    `DRM_Wrapper.exe` + `quark.jar`.

> Bu aşamadan sonra geliştirici devre dışıdır: sistem tamamen çevrimdışı
> çalışır, hiçbir ağ bağlantısı veya saat kontrolü yoktur (CLAUDE.md kural 6).

---

## Adım 1 — `DRM_Wrapper.exe` başlar ve önce kendine bakar

5. Program açılır açılmaz, hiçbir şey okumadan/yazmadan önce **debugger
   tespiti** çalışır (`anti_debug.hpp`): `IsDebuggerPresent`,
   `CheckRemoteDebuggerPresent` ve PEB'in `BeingDebugged`/`NtGlobalFlag`
   alanlarının ham bellek ofsetlerinden okunması.
6. Bu kontrollerden herhangi biri "evet, bir debugger var" derse, program
   hiçbir mesaj göstermeden, hiçbir temizlik yapmadan `exit(1)` ile anında
   kapanır (`FailDeadly()`) -- "fail-deadly" prensibinin ilk uygulaması.

## Adım 1.5 — `quark.jar`, derleme-zamanı gömülü özetiyle karşılaştırılır

Debugger taramasından hemen sonra, ama HWID toplanmadan ve kullanıcıdan
herhangi bir şey istenmeden **önce**, `DRM_Wrapper.exe` diskteki `quark.jar`
dosyasının SHA-256 özetini hesaplar ve bunu, derleme anında ikiliye gömülmüş
sabit bir özetle (`jar_digest.hpp` içindeki `kQuarkJarSha256`) `lamport::VerifyStep`
ile aynı sabit-zamanlı XOR-biriktirme deseniyle karşılaştırır. Eşleşmezse --
dosya eksik, okunamıyor, ya da (en kritik olasılık) **değiştirilmiş** -- program
`kWrapperJarIntegrityFailed` ile `FailDeadly()`'ye düşer.

Bu kontrolün varlık nedeni: bu noktaya kadar hiçbir adım `quark.jar`'ın
gerçekten *bizim* `quark.jar`'ımız olduğunu doğrulamıyordu -- C++ tarafı,
üreteceği `handoff_secret`'i, `kJvmArgs` komut satırında ne yazıyorsa ona
güvenerek borudan geçirirdi. Bu, saldırgana açık bir yol bırakırdı: `quark.jar`'ı,
sırrı `content_key` türetilmeden **önce** diske yazan veya başka bir yere
ileten sahte bir sürümle değiştirmek. `state.bin` için zaten uygulanan
"doğrula, güvenme" duruşu (CLAUDE.md kural 2), burada -- borunun karşı
ucundaki programın *kendisine* -- bir kriptografik bağlama halkası daha
eklenerek taşınmıştır. (Bilinçli olarak JRE'nin/`javaw.exe`'nin kendisi
sabitlenmemiştir -- bu, her JDK güncellemesinde yeniden üretilmesi gereken
devasa bir sabit anlamına gelirdi; "basit-sağlam" ilkesi gereği peşinde
koşulmayan bir karmaşıklık olarak bilinçli şekilde dışarıda bırakılmıştır.)

## Adım 2 — Bu makinenin parmak izi yeniden toplanır

7. `quark::hwid::Collect()`, **hiçbir önceden kaydedilmiş veriye güvenmeden**,
   bu makineden 11 bağımsız donanım/firmware/işletim sistemi kimliğini ham
   API'lerle (WMI değil) toplar: CPU kimliği+marka adı+çekirdek sayısı, anakart
   UUID'si, anakart üretici bilgisi, BIOS kimliği, dolu her RAM yuvasının
   bilgisi, sistem diskinin seri numarası, sistem biriminin seri numarası, MAC
   adresi ve Windows `MachineGuid` değeri.
8. On bir alandan **biri bile** okunamazsa, `Collect()` başarısız döner ve
   program `FailDeadly()` ile kapanır -- kısmi bir parmak izi, sahte bir parmak
   izinden daha tehlikelidir, çünkü neyin eksik olduğu bir saldırgana ipucu
   verebilir.
9. Toplanan 11 alan, sabit bir sıraya (`kFieldOrder`) göre `\x1F` baytlarıyla
   birleştirilerek tek, deterministik bir bayt dizisine -- `hwid_canonical` --
   dönüştürülür (`CanonicalBytes`). Bu dizi artık hem şifreleme hem anahtar
   türetme adımlarında kullanılacak "tek doğruluk kaynağı"dır.

## Adım 3 — `state.bin` açılır; HWID burada sadece bir kontrol değil, anahtarın kendisidir

10. `state_key = SHA256("QUARK-STATE-KEY" || uzunluk(SECRET) || SECRET || hwid_canonical)`
    hesaplanır (`DeriveStateKey`) -- yani lisans dosyasının şifre çözme anahtarı,
    hem geliştiricinin gizli sabitine hem de bu spesifik makinenin donanımına
    aynı anda bağlıdır.
11. `state.bin`, AES-256-GCM ile açılırken `hwid_canonical` doğrudan
    **Associated Authenticated Data (AAD)** olarak verilir -- yani HWID,
    "eşleşiyor mu?" diye ayrıca kontrol edilen bir değer değil, şifre çözme
    işleminin matematiğinin bizzat bir parçasıdır.
12. Tek bir donanım bileşeni bile değişmiş olsa (ör. RAM sökülmüş, disk
    klonlanmış), `hwid_canonical` baştan sona farklı bir bayt dizisi olur,
    `state_key` tamamen farklı bir anahtar olur, ve AES-GCM kimlik doğrulama
    etiketi (auth-tag) tutmaz -- bu, "yanlış makine" ile "dosya kurcalanmış"
    durumlarını **kasıtlı olarak ayırt edilemez** kılar (CLAUDE.md kural 2).
13. Açma başarısız olursa -- yanlış makine, bozuk dosya, kurcalanmış dosya,
    fark etmez -- program yine tek bir şekilde davranır: `FailDeadly()`.
14. Dosya başarıyla açıldıysa, içindeki düz metin alanı olan `hwid_digest`
    (HWID'in SHA-256'sı) yeniden hesaplanan değerle karşılaştırılır; bu,
    "dosyanın mührü doğru ama iç muhasebesi tutarsız" gibi normalde hiç
    oluşmaması gereken bir durumu yakalayan ek bir güvenlik katmanıdır.

## Adım 3.5 — `state.bin`, üç bağımsız tanıkla (dört kanal) çapraz kontrol edilir

`state.bin`'in AES-GCM mührü, dosyanın *değiştirilmediğini* matematiksel
olarak kanıtlar -- ama dosyanın bütünüyle, daha eski ve geçerli şekilde
mühürlenmiş bir kopyasıyla *yer değiştirmediğini* kanıtlayamaz (bir yedekten
geri yükleyerek zinciri "geri sarma" saldırısı). Bunu kapatmak için
`DRM_Wrapper.exe`, `state_key`'den tamamen ayrı, alan-ayrımlı
(domain-separated) **üç bağımsız anahtar** türetir ve üç ayrı depolama
kanalında, `state.bin` ile aynı AES-256-GCM + HWID-AAD mühürleme deseniyle
birer "tanık" (`quark::registry::Witness`) saklar:

| Kanal | Depolama konumu | Anahtar türetme etiketi |
|---|---|---|
| 1 (birincil) | `state.bin` (disk) | `"QUARK-STATE-KEY"` |
| 2 (ikincil) | `HKCU\Software\Quark\License` (kayıt defteri) | `"QUARK-REGISTRY-KEY"` |
| 3 (üçüncül) | `%APPDATA%\Microsoft\Windows\ThemeCache:q` (NTFS ADS) | `"QUARK-ADS-KEY"` |
| 4 (dördüncül) | `DRM_Wrapper.exe:quark` (exe üzerinde NTFS ADS) | `"QUARK-OVERLAY-KEY"` |

Her ikincil tanık, `state.bin`'in tam zincir konumunu (`anchor`,
`remaining_links`, `hwid_digest`) ve bir `high_water_unix_time` değerini
yansıtır. Üç ikincil kanaldan kaç tanesinin mevcut olduğunu belirten
`absent_count` (0–3), davranışı deterministik olarak dört duruma ayırır:

- **`absent_count == 3` → hiç tanık yok:** `state.bin`'deki `remaining_links`,
  lisansın değişmez `original_chain_length` alanına eşitse (Dev_Keygen
  tarafından mühür anında bir kere yazılan, her ileri-sarmada değiştirilmeden
  kopyalanan alan -- format v2) gerçekten "el değmemiş" bir lisanssır; üç
  tanık da mevcut konumu yansıtacak şekilde taze olarak mühürlenir. Eşit
  **değilse** -- bu lisans zaten kullanılmış ama hayatta kalan hiçbir tanık
  yoksa -- bu "tüm tanıkları sil, daha eski (kullanılmış) bir `state.bin`
  yedeğini geri yükle" saldırısının tam imzasıdır:
  `kWrapperWitnessMissingAfterUse` ile `FailDeadly()`.
- **`absent_count` 1 veya 2 → kısmi yokluk:** Bir veya iki kanal eksikken
  diğerleri mevcut -- bu, seçici olarak yapılan bir silme veya geri yüklemenin
  imzasıdır. Sonuç her zaman `kWrapperWitnessMismatch` ile `FailDeadly()`.
- **`absent_count == 0` → tüm tanıklar mevcut:** Her biri kendi başına
  kimlik doğrulamalıdır (herhangi biri başarısız olursa sırasıyla
  `kWrapperRegistryOpenFailed` / `kWrapperAdsOpenFailed` /
  `kWrapperOverlayOpenFailed`), VE üçü de `state.bin` ile byte-byte aynı
  zincir konumunu göstermelidir -- aksi halde `kWrapperWitnessMismatch`.
  Ardından `high_water_unix_time`, **üç kanalın tümü üzerinden** `max()` ile
  alınır; tek bir kanalı silerek sıfırlamak mümkün değildir. Sistem saati bu
  yüksek-su işaretinden geriye giderse `kWrapperClockRollbackDetected`.

Saat tripwire'ı **bir süre-sonu kontrolü değildir** -- CLAUDE.md kural 6
değişmemiştir; lisansın "kaç kullanım kaldığı" hâlâ ve sadece Lamport
zincirinin derinliğiyle belirlenir. İleri akan veya normal görünen bir saat
hiçbir şeyi kanıtlamaz veya vermez, yalnızca **geriye** bir sıçrama tuzağı
tetikler.

Dört-kanallı mimari, bir saldırganın "bildiği" kanalları yedekleyip geri
yüklerken farkında olmadan diğer kanalları ileri konumda bırakmasına yol açar.
Kayıt defteri + `state.bin`'i yedekleyen bir saldırgan ThemeCache ADS'ini ve
exe ADS'ini atlar; exe'yi "statik, derleme çıktısı" olarak gören biri exe
ADS'ini kopyalamayı düşünmez. Birleşik sonuç: geri yükleme girişiminin
herhangi bir kombinasyonu `kWrapperWitnessMismatch`'e gider.

Dürüstçe belirtmek gerekir ki: bu şema "kullanılmış bir yedeği geri yükle +
bazı tanıkları sil" saldırısını yakalar, ama "tüm dört kanalı aynı anda
yedekle ve geri yükle -- `state.bin` dahil" senaryosunu **tamamen**
kapatamaz; o noktada hiçbir yerde çelişen bir şey kalmamıştır. Bu, "sunucu
bileşeni yok" tasarımının kaçınılmaz bir tavanıdır (CLAUDE.md), bir eksiklik
değil.

## Adım 4 — Lisansın "süresi" kontrol edilir (saat değil, sayaç)

15. `state.bin` içindeki `remaining_links` sayacı okunur; bu sayı sıfırsa
    program `FailDeadly()` ile kapanır -- sistemde **hiçbir** `GetSystemTime`
    çağrısı yoktur, bitiş tamamen Lamport zincirinin tükenmesiyle belirlenir.

## Adım 5 — Kullanıcıdan tek kullanımlık anahtar istenir ve doğrulanır

16. Kullanıcıdan, zincirin bir önceki halkası olan `H^{k-1}(x)` değerini
    girmesi istenir (`PromptForKey`).
17. Girilen değer ayrıştırılır (`ParseKey`) ve ham girdi -- ayrıştırma
    başarılı olsa da olmasa da -- hemen bellekten silinir (`SecureZero`);
    çünkü bu bir kimlik bilgisidir ve "hatalı format" ile "yanlış anahtar"
    durumlarının dışarıdan ayırt edilememesi gerekir.
18. `SHA256(girilen_anahtar) == state.bin'deki anchor` eşitliği kontrol edilir
    (`VerifyStep`); bu, Lamport zincirinin tek yönlü (hash bir kere ileri
    gider, asla geri hesaplanamaz) doğasından gelen tekrar-oynatmaya karşı
    kanıttır.
19. Eşitlik tutmazsa -- ayrıştırma da, doğrulama da olsa -- sonuç yine aynıdır:
    `FailDeadly()`.

## Adım 6 — Zincir bir adım ileri sarılır ve **JVM açılmadan önce** diske yazılır

20. Yeni durum hesaplanır: `anchor = kullanıcının verdiği anahtar`,
    `remaining_links = eski_değer - 1`.
21. Bu yeni durum, aynı `state_key` ve aynı `hwid_canonical` (AAD) ile yeniden
    mühürlenip `state.bin`'e **atomik olarak** (geçici dosya + yeniden
    adlandırma) yazılır -- ve bu yazma, JVM başlatılmadan **önce** tamamlanır.
22. Bu sıralamanın nedeni şudur: yazma işlemi JVM'den sonra olsaydı, program
    tam o anda çökerse kullanıcı aynı anahtarı tekrar girip "bedava" bir
    kullanım hakkı kazanabilirdi -- harcama önce **kalıcı hale getirilir**,
    sonra ödül (uygulamanın çalışması) verilir.
23. Yazma başarısız olursa -- disk dolu, izin yok, fark etmez -- program yine
    `FailDeadly()` ile kapanır; çünkü harcamayı kalıcı kılamadan devam etmek,
    bir tekrar-oynatma (replay) açığı doğurur.
23a. `state.bin` başarıyla yazıldığı **anda**, Adım 3.5'teki üç ikincil tanık
    da -- aynı yeni `anchor`/`remaining_links`/`hwid_digest` değerlerini
    yansıtacak ve `high_water_unix_time`'ı `max(şimdi, üç kanalın önceki
    yüksek-su değeri)` olarak ileri taşıyacak şekilde -- aynı nefeste ve
    sırayla (kayıt defteri → ThemeCache ADS → exe ADS) yeniden mühürlenip
    kaydedilir (olası hata kodları: `kWrapperRegistryWriteFailed`,
    `kWrapperAdsWriteFailed`, `kWrapperOverlayWriteFailed`). Bu, JVM açılmadan
    **önce** *dört* deposun da taahhüt edilmesi gerektiği anlamına gelir --
    aksi halde herhangi bir tanık, gerçek konumu yansıtamaz ve bir sonraki
    açılışta `kWrapperWitnessMismatch`'e neden olur. Bilinçli olarak kabul
    edilmiş bir bedel: dört yazma arasında bir çökme, bir sonraki açılışta
    kalıcı bir `kWrapperWitnessMismatch`'e (yani lisansın tuğlalanmasına) yol
    açar -- "doğruluk, çökme altında bile kolaylığı yener" ilkesinin (zaten
    `state.bin`'i JVM'den önce yazma kararında uygulanan ilkenin) üç adım
    daha ileri taşınmış hali.

## Adım 7 — Anahtarlar türetilir, QKH2 ilk çerçevesi oluşturulur

24. Zincir ileri sarılmadan önceki konum olan `anchor_before = license.anchor`
    kaydedilir; sıfırlanmadan önce `SHA256(online_secret)` hesaplanır.
25. `handoff_secret = SHA256("QUARK-HANDOFF" || state_key || yeni_anchor || hwid || online_secret)`
    türetilir -- gizli sabite (dolaylı olarak `state_key` üzerinden), bu
    makinenin donanımına, bu açılışta harcanan zincir halkasına **ve**
    paste.rs'ten alınan `online_secret`'e aynı anda bağlıdır.
26. `online_secret` ve `candidate` (harcanan kullanıcı anahtarı) bellekten
    hemen silinir (`SecureZero`).
27. `content_key = SHA256("QUARK-CORE-CONTENT-KEY" || handoff_secret)` türetilir
    (anahtar ayrımı: tel üzerinde gözlemlenen baytlar ≠ AES anahtarı).
28. Rastgele 32 baytlık `session_id` üretilir; tüm challenge MAC'lerinde bağlam
    olarak kullanılır.
29. `initial_seal = HMAC-SHA256(key=content_key, msg="SEAL"||anchor_before||
    anchor_after||SHA256(online_secret)||hwid_canonical)` hesaplanır -- Java'nın
    tam DRM akışını doğrulaması için gerekli kriptografik kanıt.
30. `core_enc_key = SHA256("QUARK-CORE-ENC-KEY" || state_key || SHA256(online_secret) ||
    hwid_canonical)` türetilir. Bu anahtar her oturumda aynıdır (yeni anchor içermez),
    dolayısıyla `core.enc` lisans ömrü boyunca aynı dosyayla çalışır.
31. QKH2 ilk çerçevesi (`EncodeInitialFrame`) kodlanır (**136 bayt**):
    `"QKH2" + version(2) + handoff_secret(32) + session_id(32) + initial_seal(32) + core_enc_key(32)`.
    Bu işlem `handoff_secret` ve `core_enc_key` bellekte canlıyken yapılır; ardından
    her ikisi de sıfırlanır.

---

## Adım 8 — İki boru oluşturulur, JVM başlatılır

31. `LaunchJvmWithInitialHandoff`, iki anonim boru oluşturur:
    - `stdin_pipe`: okuma ucu → çocuk stdin, **yazma ucu ebeveynde açık kalır**
    - `stdout_pipe`: yazma ucu → çocuk stdout, okuma ucu ebeveynde challenge yanıtları için
32. Çocuk süreç `CreateProcessW` ile başlatılır; hiçbir sır `argv`'e yazılmaz
    (Görev Yöneticisi veya `wmic process list`'te görünmezdi -- CLAUDE.md kural 4).
33. QKH2 ilk çerçevesi `stdin_pipe` yazma ucuna yazılır; **boru kapatılmaz**.

## Adım 9 — Challenge-response döngüsü: DRM_Wrapper hayatta kalır

34. `RunChallengeLoop`, Java süreci kapanana veya öldürülene kadar bloke olur:
    - Her ~30 saniyede: `"CHAL" + counter(4) + nonce(32)` çerçevesi `stdin_pipe`'a yazılır.
    - 10 saniye içinde Java'dan 32 bayt HMAC yanıtı beklenir.
    - `HMAC-SHA256(content_key, "RESP"||session_id||counter||nonce)` sabit zamanlı
      karşılaştırmayla doğrulanır.
    - Zaman aşımı veya yanlış yanıt → `TerminateProcess(java_pid)` + return.
35. Java süreci `WaitForSingleObject` tarafından doğal çıkışla tespit edilirse
    döngü temiz şekilde sona erer. `DRM_Wrapper.exe` Java'nın çıkış kodunu döndürür.

---

## Adım 10 — `quark.jar` (Bootstrap) devreye girer ve QKH2 çerçevesini okur

36. `Bootstrap.main`, standart girişten **tam olarak** 136 bayt okur (QKH2 ilk
    çerçevesi). EOF beklemez -- boru açık kalır; ardından challenge'lar gelecektir.
37. `magic == "QKH2"` ve `version == 2` doğrulanır. Tutmazsa `System.exit(1)`.

## Adım 11 — Anahtarlar türetilir, QuarkHeartbeat ve QuarkRuntime başlatılır

38. `content_key = SHA256("QUARK-CORE-CONTENT-KEY" || handoff_secret)` hesaplanır
    (challenge-response HMAC anahtarı; her oturumda değişir).
39. `core_enc_key` çerçeveden okunur (offset 104, 32 bayt; `core.enc` şifre çözme
    anahtarı; her oturumda aynı -- bakınız Adım 30).
40. `QuarkHeartbeat` non-daemon iş parçacığı `content_key` + `session_id` kopyalarıyla
    başlatılır. Bootstrap, bu noktadan sonra stdin'i okuyamaz; `QuarkHeartbeat` sahiptir.
41. `QuarkRuntime.init(contentKey, sessionId)` çağrılır; `@QuarkCheckpoint` metodları
    bu singleton üzerinden HMAC hesaplar.
42. Bootstrap'in `contentKey` kopyası sıfırlanır.

## Adım 12 — `QuarkHeartbeat` döngüsü

43. `QuarkHeartbeat` döngüsü:
    - Stdin'den 40 baytlık `"CHAL"` çerçevesi okunur.
    - `ReadFile` başarısız olursa → ebeveyn (DRM_Wrapper) öldü → `halt(-1)`.
    - `HMAC-SHA256(content_key, "RESP"||session_id||counter||nonce)` hesaplanır.
    - 32 bayt stdout'a yazılır.
44. `Watchdog` daemon iş parçacığı: 60 saniyedir yanıt gönderilemedi ise `halt(-1)`.

## Adım 13 — `core.enc` bellekte çözülür

45. `core.enc` diskten okunur; **`core_enc_key`** AES-256-GCM anahtarı olarak kullanılır
    (not: `content_key` değil -- anahtar ayrımı).
    Yanlış anahtar → `AEADBadTagException` → `System.exit(1)`. Boolean trap yok.
46. `core_enc_key` sıfırlanır. `content_key` sadece `QuarkHeartbeat`'in kopyasında yaşamaya devam eder.

## Adım 14 — Gerçek uygulama, bellekten, doğrudan başlatılır

44. Çözülmüş baytlar `InMemoryClassLoader`'a verilir; `.class` dosyaları
    **hiçbir zaman diske yazılmadan** doğrudan bellekten tanımlanır (`defineClass`).
45. `quark.app.CoreEntryPoint.start(String[])` yansıma ile çağrılır;
    gerçek uygulama çalışmaya başlar.
46. Çözülmüş bayt arabelleği hemen sıfırlanır.

## Adım 15 — Eğer bir şey ters giderse: tek, ayırt edilemez bir son

47. Yukarıdaki adımlardan **herhangi biri** başarısız olursa -- yanlış sır,
    bozuk `core.enc`, eksik giriş noktası, yanlış challenge yanıtı, ne olursa
    olsun -- sonuç hep aynıdır: anahtarlar sıfırlanır, `Runtime.getRuntime().halt(-1)`
    çağrılır. Bu akışın **hiçbir yerinde** "lisanslı mı değil mi" diye soran bir
    `if` yoktur (CLAUDE.md kural 3); koruma, doğru bytecode'un doğru anahtar
    olmadan **fiziksel olarak var olamaması** ve challenge'lara doğru yanıt
    verilebilmesi için `content_key`'in bellekte bulunması zorunluluğudur.

---

## Tek cümlelik özet (zihninizde tutmanız gereken tek şey)

> C++ tarafı, "bu makine + bu gizli sabit + bu zincir halkası + bu paste.rs
> içeriği" dörtlüsünden bir `content_key` türetir, bunu QKH2 çerçevesine sarıp
> iki yönlü boru üzerinden Java'ya iletir ve **hayatta kalarak** her 30 saniyede
> bir challenge üretir; Java tarafı challenge'lara doğru `content_key` ile yanıt
> vererek varlığını kanıtlar ve `core.enc`'i bellekte çözer -- zincirin herhangi
> bir halkası eksik ya da yanlışsa, ya da yanıt gelmezse, her iki taraf da aynı
> sonuca ulaşır: `halt(-1)`, hiçbir ipucu, hiçbir ayrım.
