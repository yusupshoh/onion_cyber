# Muallim — Login backend (7 qatlamli, "piyoz" arxitekturasi)

FastAPI + SQLite asosida qurilgan, **ikki mustaqil jarayonga** bo'lingan
xavfsiz autentifikatsiya backendi. Faqat login qismi (`login.html`ga mos).

## Nega ikki jarayon?

Agar hammasi bitta dasturda bo'lsa, o'sha dasturni buzgan hujumchi kalitni
ham, ma'lumotni ham bir joydan topadi. Shuning uchun tizim ikkiga bo'lingan:

| | **Chegara xizmati** (`app/`) | **Vault xizmati** (`vault/`) |
|---|---|---|
| Port | `0.0.0.0:8000` (tashqi) | `127.0.0.1:8500` (FAQAT ichki) |
| Vazifasi | So'rovlarni qabul qiladi, filtrlaydi | Parollarni tekshiradi, shifrni ochadi |
| Kalitlarga ega | **Yo'q** (JWT imzolash kaliti ham yo'q — faqat public kalit) | Ha, faqat RAM'da |
| Token yaratadimi | **Yo'q** — faqat Vault bergan tokenni uzatadi | Ha (Ed25519 bilan imzolaydi) |
| Buzilsa nima bo'ladi | Parollarni ko'ra oladi, lekin token **yarata olmaydi** va foydalanuvchi **qo'sha olmaydi** | Tashqi tarmoqqa umuman ochiq emas |

Ular orasidagi har bir so'rov **HMAC bilan imzolanadi** (vaqt tamg'asi +
bir martalik nonce + **metod va yo'l** bilan: replay va "imzoni boshqa
endpoint'ga ko'chirish" hujumlaridan himoyalangan). Vault imzoni body'ni
tahlil qilishdan OLDIN tekshiradi.

## 7 qatlam (so'rov kelganda)

1. **Transport** — HSTS, CSP, X-Frame-Options va h.k. header'lar (`app/middleware/security_headers.py`)
2. **Chegara nazorati** — CORS, so'rov hajmi (haqiqiy kelgan baytlar bo'yicha, `chunked` ham), content-type (`app/middleware/cors_guard.py`)
3. **Trafik nazorati** — IP bo'yicha sirg'anuvchi oyna (reverse proxy ortida ham to'g'ri IP), xilma-xil email'larga xato urinish (credential stuffing) va ketma-ket o'xshash email'lar aniqlash; xotira cheklangan (`app/middleware/rate_limiter.py`, `app/core/client_ip.py`). Hisob bo'yicha bloklash Vault'da (pastga qarang)
4. **Validatsiya** — Pydantic qat'iy tiplashtirish (`app/schemas/auth_schemas.py`)
5-6. **Autentifikatsiya + Vault aloqasi** — imzolangan ichki so'rov, Vault Argon2id bilan (thread-pool'da, event loop'ni bloklamasdan) tekshiradi (`app/core/vault_client.py`, `vault/service.py`)
7. **Sessiya** — Vault'da imzolangan qisqa muddatli JWT (Ed25519) + Vault bazasida saqlanadigan aylanma (rotating) refresh token, httpOnly cookie (`vault/tokens.py`; chegara xizmatida faqat tekshirish: `app/core/token_manager.py`)

## Fayl ichida fayl — Vault'ning ichki tuzilishi

```
secrets/secrets.db.enc   <- foydalanuvchilar (parol-hash) shu yerda, AES-256-GCM bilan shifrlangan
secrets/keyfile.enc      <- Data Key (DK) shu yerda, KEK bilan shifrlangan
```

`KEK` (Key Encryption Key) hech qayerda saqlanmaydi — har safar Vault
ishga tushganda **4 mustaqil manbadan** qayta yig'iladi. Manbalar bir-biridan
HAQIQATAN mustaqil bo'lishi uchun ular **turli kanaldan** yetkaziladi:

| # | Manba | Qayerda turadi / qanday beriladi |
|---|---|---|
| 1 | `VAULT_ENV_SECRET` | Vault jarayonining muhiti (deploy/sir menejeri) |
| 2 | `secrets/keyring.key` | Diskda (production'da haqiqiy OS keyring/HSM/KMS bilan almashtiring) |
| 3 | Admin passphrase | **Muhitda emas**: ishga tushganda terminalda kiritiladi, yoki `ADMIN_PASSPHRASE_FILE` (sir menejeri/tmpfs). Env faqat `ALLOW_ENV_PASSPHRASE=1` (dev) bilan |
| 4 | Shamir 3-of-5 | **5 ta alohida joyda** (USB/server/administrator), `secrets/` ICHIDA EMAS. `SHAMIR_SHARE_PATHS` orqali kamida 3 tasi ulanadi |

`init_vault.py` bo'laklarni `secrets/` ichiga yozishni **rad etadi** (faqat
`--insecure-colocated-shares` dev bayrog'i bilan, ogohlantirish bilan).

Bunga qo'shimcha, 3 ta **gate** (shart) ham bajarilishi kerak:

5. Fayl ruxsati/egaligi tekshiruvi (0600/0700 dan tashqari hech kim o'qiy olmaydi)
6. HMAC yaxlitlik tekshiruvi — fayllar tashqi tomondan o'zgartirilmaganmi
7. Urinishlar sonini cheklash (KEK yig'ishga cheksiz urinib bo'lmaydi)

**Baza hech qachon diskka ochiq holda yozilmaydi** — faqat `sqlite3`ning
`:memory:` bazasida, RAM'da turadi (`serialize()`/`deserialize()` orqali).
Fayllar atomik yoziladi (tmp + fsync + rename).

## Fayl buzilishiga javob (nima HAQIQATAN avtomatik bo'ladi)

**Ishlab turgan Vault** (`vault/service.py` watchdog, har 30 soniyada):
`keyfile.enc`, `secrets.db.enc` va ularning `.hmac` fayllarini Vault **o'zi
oxirgi yozgan** SHA-256 izi (faqat RAM'da) bilan solishtiradi. Farq topilsa:
alert (`secrets/alerts.log`) → **Data Key almashtiriladi** → hamma dinamik fayl
RAM'dagi haqiqiy nusxadan qayta yoziladi. Ya'ni tashqaridan buzilgan yoki
o'chirilgan fayl o'zi tiklanadi. Statik fayllar (`keyring.key`, `passphrase.salt`,
`integrity.key`) o'zgarsa — RAM'dan tiklab bo'lmaydi, faqat alert beriladi.
(Bu tekshiruv `integrity.key`ga bog'liq emas — u ham `secrets/` ichida turadi.)

**Ishga tushish paytida** yaxlitlik buzilgan bo'lsa: Vault OCHILMAYDI (RAM'da
hali nusxa yo'q, shuning uchun kalit almashtirib bo'lmaydi), alert yoziladi,
administrator zaxiradan tiklashi kerak. Oddiy noto'g'ri parol (`DecryptionError`)
bilan haqiqiy fayl buzilishi (`TamperDetected`) chalkashtirilmaydi.

**Yozish crash-safe** (jarayon/elektr istalgan nuqtada to'xtasa ham vault ochiladi):
har fayl `tmp → fsync → rename` bilan yoziladi; `.hmac` faylida yozish paytida YANGI va ESKI
imzo birga turadi; kalit almashtirishda yangi DK avval `keyfile.enc.next` jurnaliga yoziladi, so'ng
baza, so'ng keyfile. Baza yangi DK bilan yozilib keyfile eski qolsa, `unlock_vault` jurnaldan
tugatadi. Bu 12 ta crash nuqtasida avtomatik test qilinadi (`tests/test_units.py`).

**Imzosiz/soxta so'rovlar** Vault'ga bevosita kelsa: faqat **alert**. Kalit
almashtirilmaydi — chunki bunday so'rov kalit oshkor bo'lganini bildirmaydi
(HMAC kalitini taxmin qilib bo'lmaydi), almashtirish esa hech narsani yaxshilamaydi.

**DK almashtirish nima beradi:** eski DK bilan shifrlangan eski nusxa/zaxira
joriy keyfile bilan mos kelmaydi. **Nima bermaydi:** KEK oshkor bo'lgan bo'lsa,
DK almashtirish uni qaytarmaydi — u uchun KEK manbalarini (env sekret, passphrase,
Shamir) almashtirish kerak (yangi `init_vault` + foydalanuvchilarni ko'chirish).

## Ishga tushirish (Linux/WSL, Python 3.10+)

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# 1) IKKI alohida env fayl (sirlar chegara xizmatiga berilmaydi):
cp .env.vault.example  .env.vault     # VAULT_ENV_SECRET, PASSWORD_PEPPER, INTERNAL_SIGNING_KEY ...
cp .env.border.example .env.border    # faqat INTERNAL_SIGNING_KEY (Vault'dagi bilan bir xil) + CORS ...
python3 -c "import secrets; print(secrets.token_hex(32))"   # har bir sir uchun alohida

# 2) Vault'ni BIR MARTA sozlash — 5 ta ALOHIDA joy (USB/server/admin):
(set -a; . ./.env.vault; set +a
 python3 scripts/init_vault.py --share-dirs /mnt/usb1/s /mnt/usb2/s /srv/a2/s /srv/a3/s /srv/a4/s)
#   dev/demo uchun: --insecure-colocated-shares  (Shamir foydasi yo'q!)

# 3) Foydalanuvchi yaratish — OFFLAYN, Vault to'xtatilgan holda (HTTP endpoint yo'q):
(set -a; . ./.env.vault; set +a; python3 scripts/create_user.py sizning@email.uz)

# 4) Ikkala xizmatni ALOHIDA terminalda, ALOHIDA muhit bilan:
(set -a; . ./.env.vault;  set +a; SHAMIR_SHARE_PATHS=/mnt/usb1/s:/mnt/usb2/s:/srv/a2/s \
   uvicorn vault.service:app --host 127.0.0.1 --port 8500)    # passphrase'ni so'raydi
(set -a; . ./.env.border; set +a; uvicorn app.main:app --host 0.0.0.0 --port 8000 --no-server-header)
```

Eski vault'dan o'tish: Vault'ni to'xtating, `python scripts/distribute_shares.py D1 D2 D3 D4 D5`
bilan bo'laklarni `secrets/` dan chiqaring (DB sxemasi ochilganda avtomatik yangilanadi;
eski chegara-xizmati `data/sessions.db` va eski JWT sirlari endi ishlatilmaydi — mavjud
sessiyalar bekor bo'ladi, foydalanuvchilar qayta kiradi).

`login.html`dagi formadan `POST http://localhost:8000/auth/login` ga
`{"email": "...", "password": "..."}` yuborilishi kerak.

## Login bloklash: enumeration, timing va lockout-DoS (`vault/login_throttle.py`)

| Muammo | Yechim |
|---|---|
| Email enumeration (mavjud email `423`, mavjud emas `401`) | Bloklash **har qanday email satri** uchun bir xil yuritiladi; javoblar aynan bir xil (5 ta xatodan keyin ikkalasi ham `423`) |
| Timing enumeration | Mavjud bo'lmagan email uchun ham aynan bitta Argon2 `verify` (oldindan hisoblangan soxta hash bilan) |
| Lockout-DoS (birovning emailini 5 marta xato kiritib bloklash) | Asosiy blok **(email, manba-IP)** juftligi bo'yicha: hujumchi faqat o'z manbasidan bloklanadi, haqiqiy ega o'z IP'sidan kira oladi |
| Tarqoq brute-force (ko'p IP'dan bitta hisob) | Hisob bo'yicha umumiy oyna (15 daqiqada 30 xato) → **noma'lum** manbalar bloklanadi; egasi ilgari kirgan manbalar (`known_sources`, IP xeshi) bloklanmaydi |
| Event loop bloklanishi (64 MB Argon2 sinxron) | `asyncio.to_thread` + bir vaqtda ARGON_CONCURRENCY (4) cheklovi |
| Har xato urinishda bazani qayta yozish | Hisoblagichlar RAM'da; baza faqat muvaffaqiyatli kirishda yoziladi |

Refresh token aylantirishda **10 soniyalik grace davri**: ikki brauzer tabi bir vaqtda
yangilasa, bu o'g'irlik deb hisoblanib barcha sessiyalar o'chirilmaydi. Kompromiss: o'g'ri
aynan shu soniyalarda ishlatsa o'tadi. Grace tugagach qayta ko'rsatilgan token = o'g'irlik.

**Reverse proxy ortida**: `TRUSTED_PROXIES=10.0.0.0/8,...` bering. `X-Forwarded-For` faqat
shu manzillardan kelganda hisobga olinadi va o'ngdan chapga yurib birinchi ishonchsiz
manzil olinadi (chapga soxta IP qo'shish foyda bermaydi). Aks holda hamma foydalanuvchi
proxy IP'si ostida bitta chelakka tushadi.

## Testlar

```bash
pip install -r requirements.txt -r requirements-dev.txt
python3 -m pytest            # ~1 daqiqa; Linux/WSL, Python 3.10+
```
33 ta test: Shamir (har qanday 3/5), throttle, rate-limiter, client-IP, **kalit almashtirish va
saqlashning HAR BIR yozish nuqtasida jarayon to'xtashi (crash) simulyatsiyasi**, hamda ikkita
HAQIQIY jarayon (Vault + Chegara) bilan end-to-end: login/refresh/o'g'irlik/grace, soxta token,
alg-confusion, buzilgan Chegara stsenariysi, enumeration, lockout-DoS, tarqoq brute-force,
chunked body, runtime tamper → tiklash → qayta ishga tushirish.

## Endpoint'lar

| Endpoint | Vazifasi |
|---|---|
| `POST /auth/login` | Email+parol -> access_token (JSON) + refresh_token (httpOnly cookie) |
| `POST /auth/refresh` | Cookie orqali yangi access_token (eski refresh token bekor qilinadi) |
| `POST /auth/logout` | Refresh tokenni bekor qiladi |

## Immutable himoya — fayllarni o'chirish/o'zgartirishning OLDINI OLISH

Yuqoridagi HMAC/imzo mexanizmlari fayl **buzilganini ANIQLAYDI** (tamper
detection) - lekin buzilishning o'zini to'xtatmaydi. `vault/immutability.py`
esa bir qadam oldinga o'tadi: Linux'ning `chattr +i` ("immutable")
atributi orqali, fayllarni **OS darajasida** o'chirib yoki ustidan yozib
bo'lmaydigan qiladi - hatto root foydalanuvchi ham, avval maxsus buyruq
bilan atributni olib tashlamasdan, buni qila olmaydi.

**Ikki toifa:**
- **Statik fayllar** (`keyring.key`, `passphrase.salt`, Shamir bo'laklari,
  `integrity.key`) - sozlashdan keyin hech qachon o'zgarmaydi, bir marta
  immutable qilinadi va boshqa hech qachon tegilmaydi.
- **Dinamik fayllar** (`keyfile.enc`, `secrets.db.enc`, ularning `.hmac`
  fayllari, `attempt_state.json`, `rotation_state.json`) - ishlash
  paytida o'zgarishi kerak, shuning uchun `mutable_window()` orqali
  vaqtincha ochiladi, yoziladi, qayta yopiladi - **har bir ochish log
  qilinadi** (`vault/service.py` va Vault loglariga qarang).

**Sinovda tasdiqlandi:** to'g'ridan-to'g'ri `rm` va `echo > fayl` (ustidan
yozish) ikkalasi ham `Operation not permitted` bilan rad etildi, lekin
dasturning o'zi (login, rotatsiya) baribir muvaffaqiyatli yoza oldi -
chunki u atributni nazorat ostida, vaqtincha olib tashlaydi.

**Qo'shimcha foyda:** bu, oldin alohida muammo sifatida aytilgan
`rotation_state.json`ning imzosiz bo'lishi zaifligini ham yopadi - endi
uni fayl darajasida o'zgartirib bo'lmaydi, HMAC qo'shishga hojat qolmadi.

**MUHIM CHEKLOVLAR (halol eslatma):**
- Faqat **ext2/3/4** kabi fayl tizimlarida ishlaydi. Docker'ning
  **overlay2** fayl tizimi yoki **NFS** kabi tarmoq disklari buni
  qo'llab-quvvatlamasligi mumkin - bunday holda `make_immutable()` aniq
  ogohlantirish chiqaradi va HMAC/imzo qatlami yagona himoya bo'lib qoladi
- **CAP_LINUX_IMMUTABLE** huquqi kerak (odatda root, yoki shu huquq
  alohida berilgan xizmat foydalanuvchisi). Bu degani - dasturning o'zi
  himoyani vaqtincha "ochish"ga qodir, demak dastur jarayonini to'liq
  egallagan hujumchi ham nazariy jihatdan shunday qila oladi. Bu
  **qo'shimcha to'siq**, mutlaq kafolat emas - asosiy maqsadi tashqi
  (fayl tizimiga alohida kirgan, lekin dastur jarayonini egallamagan)
  hujumchini to'xtatish
- Production'da qo'shimcha, mustaqil qatlam sifatida **papka darajasidagi
  ruxsat ajratish** tavsiya etiladi: `secrets/` papkasi xizmat ishga
  tushirilgan foydalanuvchidan BOSHQA, alohida "vault-admin" egasiga
  tegishli bo'lib, xizmat foydalanuvchisi papkaga yozish huquqiga umuman
  ega bo'lmasligi kerak (`chmod 555`) - fayl o'chirish papkaga yozish
  huquqini talab qiladi, shuning uchun bu immutable atributga bog'liq
  bo'lmagan, mustaqil to'siq bo'ladi

## Production uchun MUHIM eslatmalar (bu implementatsiyaning chegaralari)

Bu implementatsiya barcha asosiy mexanizmlarni **haqiqiy va ishlaydigan**
holda amalga oshiradi (test qilingan), lekin production'ga chiqarishdan oldin:

- **OS keyring** — hozir oddiy fayl bilan simulyatsiya qilingan; haqiqiy
  muhitda `keyring` kutubxonasi yoki bulut KMS (AWS KMS, GCP KMS, HashiCorp
  Vault) ishlatilishi kerak
- **mTLS** — Chegara↔Vault aloqasi hozir HMAC bilan imzolangan (ishlaydi va
  xavfsiz), lekin ishlab chiqarishda mTLS yoki Unix socket + fayl ruxsati
  bilan qo'shimcha mustahkamlash tavsiya etiladi
- **Tarmoq izolyatsiyasi** — Vault xizmati alohida konteyner/tarmoq
  segmentida ishlashi kerak, hozir ikkalasi bir xil mashinada (demo uchun)
  ishlaydi
- **Rate-limiter (chegara) va login-throttle (Vault) xotirasi** — jarayon RAM'ida
  (bitta server uchun to'g'ri); ko'p serverli muhitda chegara hisoblagichlari Redis
  kabi umumiy xotiraga ko'chirilishi kerak. Vault restarti throttle'ni nolga tushiradi
- **CAPTCHA** — "shubhali qurilma" aniqlanganda hozir vaqtinchalik
  cooldown qo'llaniladi; production'da bu o'rinda haqiqiy CAPTCHA (masalan
  hCaptcha) qo'shilishi mumkin
- **Admin passphrase** — endi muhitda saqlanmaydi (interaktiv / `ADMIN_PASSPHRASE_FILE`).
  Natija: har restartda administrator va kamida 3 ta Shamir bo'lagi egasi kerak —
  nazoratsiz avto-restart mumkin emas (bu atayin tanlangan savdo)

## Tuzatilgan zaiflik: 7-qatlam (urinishlar hisoblagichi) endi mustaqil

Dastlabki versiyada `secrets/attempt_state.json` oddiy (imzosiz) fayl edi -
agar hujumchi allaqachon fayl tizimiga yozish huquqiga ega bo'lgan bo'lsa
(5-qatlamni chetlab o'tgan bo'lsa), u shu faylni o'chirib, muvaffaqiyatsiz
urinishlar hisoblagichini nolga tushirib qo'yishi mumkin edi.

Endi (`vault/key_sources.py`, `AttemptThrottle`):
- Holat fayli **HMAC bilan imzolanadi**
- Faylning **yo'qligi** endi "0 ta urinish" deb emas, balki **shubhali
  holat** deb qaraladi va darhol 1 soatlik bloklashga sabab bo'ladi
- Faylning **qo'lda o'zgartirilgani** (imzo mos kelmasa) xuddi shunday
  aniqlanadi va favqulodda kalit almashtirish signalini beradi
- Oddiy (imzosi to'g'ri) urinishlar hisoblanishi bilan **TAMPER** holati
  aniq ikki xil xato turi bilan ajratiladi (`GateError` vs `TamperDetected`)

Bu barcha to'rtta holat (`vault/vault_core.py`) qo'lda ishga tushirilib
sinovdan o'tkazildi.


## Haqiqiy xavfsizlik modeli (nimadan himoya qiladi, nimadan yo'q)

| Hujum stsenariysi | Natija |
|---|---|
| `secrets/` papkasi yoki zaxira nusxasi o'g'irlandi (env, passphrase va Shamir bo'laklarisiz) | **Himoyalangan** — KEK 4 mustaqil manbasiz tiklanmaydi. Bu sxemaning asosiy kuchi |
| Faqat 1–2 Shamir bo'lagi / faqat env / faqat passphrase oshkor bo'ldi | **Himoyalangan** (boshqa manbalar yetishmaydi) |
| **Chegara xizmati** to'liq egallandi | Parollar o'tayotganda ko'rinadi (muqarrar). **Lekin**: istalgan email uchun token yasay olmaydi (kalit Vault'da), foydalanuvchi yarata olmaydi (endpoint yo'q), parolni bilmagan akkaunt uchun Vault'dan token ololmaydi. Imzo `INTERNAL_SIGNING_KEY` bilan faqat `login/refresh/logout` ga ruxsat beradi |
| Ishlab turgan Vault fayllari tashqaridan buzildi/o'chirildi | Aniqlanadi (≤30s), DK almashtiriladi, fayllar RAM'dan tiklanadi, alert yoziladi |
| **Vault jarayoni** egallandi / root hujumchi | **Himoya yo'q** — KEK va DK RAM'da. `harden_process()` faqat core dump o'chiradi va `PR_SET_DUMPABLE=0` bilan boshqa oddiy jarayonlarning ptrace/`/proc/<pid>/mem` o'qishini to'sadi |
| Xizmat host'ida root | Yuqoridagining hammasi chetlab o'tiladi |

**Hali ochiq qolgan cheklovlar (yashirmaymiz):**
- **Rollback/replay:** `secrets/` ga yozish huquqi va `integrity.key` ni o'qiy olgan hujumchi eski (lekin to'g'ri) `keyfile.enc`+`secrets.db.enc` juftligini HMAC'ni qayta hisoblab qo'ya oladi; ishga tushish paytida buni aniqlab bo'lmaydi. Ishlab turgan Vault buni RAM izi bilan topadi. To'liq yechim: tashqi monoton hisoblagich/TPM yoki imzolangan zaxira.
- Python xotirasidagi kalitlarni ishonchli nolga tushirib bo'lmaydi.
- `VAULT_ENV_SECRET` va `PASSWORD_PEPPER` hamon muhit o'zgaruvchisi (`PR_SET_DUMPABLE=0` oddiy foydalanuvchilardan to'sadi, root'dan emas).
- Parol Chegara xizmatidan ochiq holda o'tadi (egallansa ko'rinadi). To'liq oldini olish uchun mijoz tomonida OPAQUE/SRP kabi PAKE protokol kerak — bu loyiha doirasida emas.
- **Windows:** kod `chattr`/`prctl` siz va fayl-ruxsat gate'ini o'chirib (ogohlantirish bilan) ishlashga mo'ljallangan, lekin **sinab ko'rilmagan**; testlar faqat Linux'da. Production uchun Linux/WSL.
- Chegara xizmatining rate-limiter holati bitta jarayon uchun; bir nechta worker bo'lsa har birida alohida.
- Refresh tokenlarni egasining qurilmasiga bog'lash (device binding) yo'q.
