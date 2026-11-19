# Quark End-to-End Test Guide

Bu rehber Windows VM'de tam uçtan uca testi nasıl çalıştıracağını açıklar.
paste.rs gerekmez — tüm testler `--dev` moduyla çevrimdışı çalışır.

---

## 1. Ön Koşullar

Windows VM'de şunlar kurulu olmalı:
- Visual Studio 2022 (MSVC, C++ workload)
- CMake 3.20+
- JDK 17+ (`JAVA_HOME` set edilmiş olmalı)
- Git (mbedTLS fetch için internet erişimi ilk build'de gerekli)

---

## 2. C++ Build

Visual Studio Developer Command Prompt (x64) aç:

```
cd C:\path\to\Quark
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

Çıktılar: `build\Release\HWID_Extractor.exe`, `Dev_Keygen.exe`, `DRM_Wrapper.exe`, `handoff_spy.exe`

---

## 3. Java Build

```
cd java
gradlew :drm-core:jar :quark-sdk:jar :test-app:jar
```

Çıktılar:
- `java\drm-core\build\libs\quark.jar`
- `java\quark-sdk\build\libs\quark-sdk.jar`
- `java\test-app\build\libs\test-app.jar`

```
cd tools
gradlew :quark-protect:jar :quark-build:jar :e2e-test:jar
```

Çıktılar:
- `tools\quark-protect\build\libs\quark-protect.jar`
- `tools\quark-build\build\libs\quark-build.jar`
- `tools\e2e-test\build\libs\e2e-test.jar`

---

## 4. jar_digest.hpp Güncelle

`DRM_Wrapper.exe` `quark.jar`'ın SHA-256'sını compile-time'da kontrol eder.
Her jar rebuild sonrası bu adımı tekrarla:

```
certutil -hashfile java\drm-core\build\libs\quark.jar SHA256
```

Çıktıyı `cpp\drm_wrapper\jar_digest.hpp` içine yaz, sonra C++ build'i tekrar çalıştır.

---

## 5. Test Dizinini Hazırla

Test runner'ın ihtiyaç duyduğu tüm dosyaları tek bir `test_bin\` dizininde topla:

```
mkdir test_bin
copy build\Release\HWID_Extractor.exe test_bin\
copy build\Release\Dev_Keygen.exe      test_bin\
copy build\Release\DRM_Wrapper.exe     test_bin\
copy build\Release\handoff_spy.exe     test_bin\
copy java\drm-core\build\libs\quark.jar              test_bin\
copy tools\quark-protect\build\libs\quark-protect.jar test_bin\
copy tools\quark-build\build\libs\quark-build.jar     test_bin\
copy java\test-app\build\libs\test-app.jar            test_bin\
```

---

## 6. Testleri Çalıştır

```
java -jar tools\e2e-test\build\libs\e2e-test.jar test_bin
```

Tek bir senaryo çalıştırmak için:
```
java -jar tools\e2e-test\build\libs\e2e-test.jar test_bin --scenario happy_path
java -jar tools\e2e-test\build\libs\e2e-test.jar test_bin --scenario wrong_key
java -jar tools\e2e-test\build\libs\e2e-test.jar test_bin --scenario exhausted
java -jar tools\e2e-test\build\libs\e2e-test.jar test_bin --scenario burned
java -jar tools\e2e-test\build\libs\e2e-test.jar test_bin --scenario tampered_state
java -jar tools\e2e-test\build\libs\e2e-test.jar test_bin --scenario full_java
```

---

## 7. Senaryo Açıklamaları

| Senaryo | Ne test eder | Beklenen sonuç |
|---|---|---|
| `happy_path` | HWID → keygen (--dev) → DRM_Wrapper → handoff_spy (1 challenge) | exit 0 |
| `wrong_key` | Yanlış unlock key | exit 1 (kWrapperUnlockKeyInvalid) |
| `exhausted` | 1-key zincir harcandıktan sonra tekrar deneme | exit 1 (kWrapperLicenseExhausted) |
| `burned` | `--burn` ile oluşturulan state.bin | exit 1 (kWrapperWitnessMissingAfterUse) |
| `tampered_state` | state.bin'de 1 byte flip | exit 1 (kWrapperStateOpenFailed) |
| `full_java` | quark-protect → quark-build → core.enc → gerçek quark.jar + TestCoreEntryPoint | exit 0 |

---

## 8. Zaman Beklentileri

Her senaryo handoff_spy'ın ilk challenge için 30s beklemesini gerektirir
(`QUARK_SPY_CHALLENGES=1` env var ile handoff_spy 1 cycle'da çıkar).

- `happy_path`: ~35 saniye
- `wrong_key` / `tampered_state` / `burned`: ~5 saniye (challenge'a ulaşamadan çıkar)
- `exhausted`: ~70 saniye (iki launch: ilki 35s, ikincisi 5s)
- `full_java`: ~40 saniye

Toplam süre: ~3-4 dakika

---

## 9. Manuel Dev_Keygen --dev Test

Test runner kullanmadan manuel olarak:

```
# 1. HWID topla
HWID_Extractor.exe hwid.json

# 2. Lisans oluştur (paste.rs yok)
Dev_Keygen.exe hwid.json 5 out_dir --dev --label "test"

# 3. DRM_Wrapper çalıştır (handoff_spy jre\bin\javaw.exe olmalı)
mkdir out_dir\jre\bin
copy handoff_spy.exe out_dir\jre\bin\javaw.exe
copy quark.jar out_dir\
copy DRM_Wrapper.exe out_dir\
cd out_dir
DRM_Wrapper.exe
# → unlock key sor: unlock_keys.txt'den ilk key'i gir
```

---

## 10. Lisans İptal (DEV)

```
# Yeni exhausted state.bin oluştur
Dev_Keygen.exe --burn hwid.json out_revoked

# Müşteri makinesindeki state.bin ile değiştir
copy out_revoked\state.bin <customer_dir>\state.bin
# Bir sonraki DRM_Wrapper çalışmasında kWrapperWitnessMissingAfterUse ile ret
```

Paste.rs olan production ortamında ek olarak:
```
Dev_Keygen.exe --revoke <paste_id> --registry licenses.txt
```
Bu online witness'ı da siler, kWrapperOnlineFetchFailed de tetiklenir.
