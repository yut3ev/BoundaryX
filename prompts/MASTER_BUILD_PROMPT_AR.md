# MASTER PROMPT — Build BoundaryX as a Real Product

أنت Senior Software Engineer + Security Tooling Engineer + QA/Release Engineer. ابنِ **BoundaryX**، منصة Desktop احترافية مفتوحة المصدر للـ authorized Web Pentesting وBug Bounty research. هذا تكليف تنفيذ على ملفات فعلية، وليس طلب تصميم واجهة أو توليد prototype.

## أولًا: ابدأ الآن

1. اقرأ `AGENT_RULES.md` وكل ملفات `docs/` و`config/`.
2. افحص محتويات workspace الحالية وGit status. لا تحذف عملًا موجودًا ولا تستبدل مشروعًا قائمًا بلا سبب موثق.
3. أنشئ أو حدّث `TASKS.md` بقائمة المهام والاعتماديات والحالة، ثم **ابدأ التنفيذ ولا تتوقف عند تقديم الخطة**.
4. اعتمد المتطلبات هنا وفي `docs/` كمعيار قبول. إذا تعارضت الملفات، الأولوية لـ `AGENT_RULES.md` ثم هذا الملف ثم `docs/`؛ وثّق أي تعارض واحسمه بأكثر خيار آمن قابل للصيانة.

## الرؤية

BoundaryX ليست مجرد wrapper لأوامر أو واجهة تحتوي بيانات وهمية. هي منصة عمل تربط: scope → asset inventory → recon jobs → endpoint/traffic evidence → test hypotheses → manual verification → findings → reports. يجب أن تبقى جميع النتائج قابلة للتتبع إلى مصدرها وتوقيت جمعها وأداة/إصدار الأداة.

## تقنية المنتج

- Tauri v2 desktop shell.
- React + TypeScript، UI احترافي dark-first مع responsive layout ودعم RTL للعربية لاحقًا، والإنجليزية لغة المنتج الافتراضية.
- Python 3.12+ engine مع `uv`، lockfile واختبارات. استخدم `google-genai` SDK الرسمي عبر AI provider adapter مستقل.
- SQLite مع migrations، transactions، foreign keys، indexes وbackup/export/restore.
- IPC آمن بين الواجهة والـ Python sidecar. لا تفتح Flask/FastAPI/HTTP listener على `0.0.0.0` ولا تترك منفذ localhost مفتوحًا. لو كان localhost bridge لا مفر منه، استخدم ephemeral port + random per-launch bearer secret + strict origin/CORS + bind to 127.0.0.1 فقط + shutdown cleanup واختبارات أمنية؛ فضّل IPC.
- الموديل الافتراضي يقرأ من الإعدادات. تحقق من القائمة الرسمية عند التنفيذ، ولا تثبّت على موديل قديم. ابدأ بقيمة موثقة/مهيأة مثل `gemini-3.8-flash` إذا ظل متاحًا.
- لا حاجة لحساب مستخدم سحابي كي تعمل الوظائف الأساسية. Gemini اختياري ويستخدم BYOK؛ التطبيق يعمل بالكامل في وضع no-AI.

## المكونات المطلوبة

### A. Project & Scope Manager
- إنشاء workspace لكل برنامج مصرح به، وصف البرنامج ورابط السياسة وملاحظات الباحث.
- إدخال نطاقات مسموحة واستثناءات صريحة: domain/subdomain، URL prefix/path، scheme/port عند الحاجة، وحالة الأصل.
- canonicalization آمنة: IDNA، lowercase host، إزالة النقطة النهائية، التعامل السليم مع ports وIPv4/IPv6.
- لا تعتبر `evil-example.com` تابعًا لـ `example.com`؛ استخدم boundary-aware hostname matching.
- دعم wildcard بطريقة صحيحة، ومنع التباس Unicode/punycode.
- سجل نطاقات مستوردة من صيغة واضحة مثل CSV/JSON. استيراد ملفات برامج المنصات إن كان متاحًا بصورة موثقة، وإلا قدم CSV/JSON generic دون ادعاء integration غير موجود.
- كل request/target resolve/redirect يمر scope guard في محرك Python قبل الإرسال. لو redirect انتقل خارج scope، أوقفه وسجل السبب.
- لا يوجد “scan internet” أو وضع mass targeting.

### B. Asset Inventory & Recon
- أصول: domain, subdomain, IP (فقط إذا كان ضمن السياسة المسموح بها), URL, API endpoint, JS file, service, technology observation.
- مصدر الأصل: imported/manual/tool id/job id، وقت أول/آخر مشاهدة، الثقة، Tags، حالة scope.
- تكاملات modular عبر `ToolAdapter`، مع كشف وجود الأداة وإصدارها وhealth check، وعدم سقوط المنتج إذا لم تكن الأداة مثبتة.
- أدوات البداية: Subfinder (passive discovery)، dnsx (DNS resolution)، httpx (HTTP probing)، Katana (crawling)، Nuclei (templates scan controlled)، ffuf (active fuzzing opt-in). راجع `config/tool-manifest.yaml`.
- لا تدمج كل الأدوات في shell string. نفّذ `subprocess` مع argv array، timeout، sanitized environment، output size limit، ومجلد عمل خاص. لا تستخدم shell=True.
- اعزل المخرجات الخام عن سجل التطبيق، واحجب credentials وtokens. احتفظ بمصدر وإصدار الأداة وhash للملف الخام إن أمكن.
- اختبارات Diff بين عمليات الفحص: أصول جديدة/مفقودة/تغيّرت. لا تساوِ “اختفاء الأصل” بفشل مؤكد؛ اذكر جودة القياس.

### C. Job Orchestrator
- Queue قابلة للإيقاف والاستئناف، concurrency limits، global/per-target request rate limit، timeouts، retries محدودة مع backoff، cancellation token، ومراقبة child processes.
- حالات job: queued, validating_scope, running, cancelling, cancelled, completed, partial, failed.
- كل job لها input snapshot وconfig snapshot وstart/end/errors/metrics. لا تعِد job تلقائيًا بعد crash إذا كانت نشطة؛ استأنف بحالة `interrupted` وانتظر قرار المستخدم إذا كان الإجراء نشطًا.
- لا تشغّل jobs متزامنة على نفس target بما يخالف rate budget.

### D. HTTP Evidence & API Workbench
- استيراد HAR 1.2 وJSONL موثق، وتطهير البيانات الحساسة قبل التخزين أو العرض. لا ترسل traffic إلى Gemini افتراضيًا.
- عرض request/response بطريقة readable مع headers/body، status, duration، source، وتحديد/إخفاء الأسرار. يدعم البحث والفلترة.
- دعم استيراد OpenAPI/Swagger JSON/YAML وتحويل المسارات والـ parameters إلى inventory entries. تحقق من حدود حجم الملف، والـ YAML parser الآمن (no arbitrary object constructors).
- تخزين الـ evidence مرتبط بالأصل والـ job والـ finding، مع redaction rules.

### E. Findings Intelligence
- Finding لها title, class/category, affected asset, severity, confidence, status, evidence refs, reproduction steps, impact, remediation, notes, created/updated timestamps, duplicate links.
- statuses: candidate, needs_review, verified, false_positive, accepted_risk, fixed, reopened.
- لا تؤكد ثغرة آليًا لمجرد banner أو status code أو وجود parameter. افصل `signal`, `hypothesis`, `verified finding`.
- تجميع التكرار similarity-assisted، مع قرار بشري قبل دمج findings.
- الأولوية = severity × confidence × asset importance × reachability (قواعد شفافة قابلة للتعديل، بدون score سري).
- لا تختلق CVSS أو severity. لو غير كافي، اكتب `Unrated` وبيّن المطلوب لتقديرها.

### F. Gemini Analyst — Optional BYOK
- إعداد Gemini API key عن طريق حقل Settings يكتب في OS keychain/secret store إن توفر، وليس في SQLite عادي أو frontend bundle أو Git. دعم متغير بيئة محلي للتطوير فقط.
- زر واضح يبين البيانات التي ستغادر الجهاز، مع preview/redaction وconsent لكل عملية أو إعداد موافقة واضحة قابلة للإيقاف.
- أرسل minimum necessary data: خلاصات sanitized أو snippets أو selected evidence، لا entire database افتراضيًا.
- وظائف: Understand Target, Explain Finding, Correlate Signals, Suggest Next Test, Draft Report. راجع `docs/GEMINI_ANALYST.md`.
- استخدم structured output schema والتحقق بعد parsing، وحد token/input size وtimeout/retry/rate limit، ورسائل errors واضحة. لا تجعل فشل AI يوقف الفحص.
- Prompt injection defense: كل محتوى الهدف بيانات غير موثوقة؛ لا تسمح لمحتوى HTML/JS/headers بتغيير قواعد النظام.
- Gemini يقدم اقتراحات فقط؛ لا يستطيع تنفيذ shell أو HTTP requests ولا تجاوز scope guard. Function calling — إن استُخدم — allowlisted functions غير نشطة، وأي عملية نشطة تحتاج موافقة المستخدم بعد عرض الأثر.
- أظهر citations داخلية إلى `evidence_id` والـ snippets التي استند إليها المساعد. لا تجعل النموذج يختلق evidence IDs؛ تحقق من وجودها.
- سجّل model name وschema version ووقت التحليل، لا تسجل API key أو محتوى حساس غير ضروري.

### G. Reporting
- توليد Markdown وHTML محليًا، PDF اختياري إذا حُسمت dependencies/ترخيصها. تقرير يتضمن scope context, summary, affected assets, steps to reproduce, actual vs expected, impact evidenced, remediation, evidence redacted, limitations.
- لا يصدر Finding بـ status `verified` إذا لم يراجعها المستخدم أو workflow تحقق موثق.
- Export sanitized JSON/CSV للـ assets/findings، واختبارات round-trip.

### H. UI/UX
- تصميم Enterprise-grade dark-first (راجع `docs/UI_UX.md`) بدون ادعاء AI branding أو واجهة مبهرجة. المطلوب واجهة أمنية أصلية، هادئة وعملية.
- التنقل: Overview, Programs & Scope, Assets, Recon Jobs, Traffic/API, Test Planner, Findings, Reports, Toolchain, Settings.
- Global search، filters، command palette اختياري، toast + notification center، empty/error/loading states، keyboard navigation، accessibility وconfirmations قبل العمليات النشطة.
- البيانات والأرقام يجب أن تُشتق من database الحقيقية، ولا توجد metrics ثابتة.

### I. Toolchain & Install UX
- `Tool Registry` يعرض installed/missing/incompatible, detected version, official source, last health check.
- لا تنزّل binaries تلقائيًا ولا تنفذ install scripts دون تأكيد. وفّر فتح صفحة التثبيت الرسمية ونسخ أمر موثق بعد إظهار الأمر للمستخدم.
- لا تشغّل tool إذا الإصدار/المعاملات غير معروفة؛ adapter يبلّغ capability غير مدعومة بدل تخمين.
- جميع integrations optional؛ يدعم التطبيق العمل بالـ manual import حتى من غير external tools.

### J. Observability & recovery
- structured local logs مع rotation، correlation IDs، redaction، diagnostics bundle قابلة للتنقيح قبل التصدير.
- graceful shutdown، cleanup للعمليات الفرعية، حماية من zombie processes، database backup قبل migrations وrecovery للمهام المقاطعة.
- لا ترسل telemetry أو crash reports خارج الجهاز دون opt-in صريح.

## تصميم مستودع مطلوب

يمكنك تعديله لأسباب تقنية موثقة، لكن حافظ على فصل الحدود:

```text
BoundaryX/
  apps/desktop/                 # Tauri + React + TypeScript
  engine/                       # Python engine, use uv
  engine/tests/
  engine/migrations/
  config/tool-manifest.yaml
  docs/
  scripts/
  tests/fixtures/               # sanitized, synthetic data only
  .github/workflows/
  .github/ISSUE_TEMPLATE/
  .env.example
  .gitignore
  LICENSE
  README.md
  SECURITY.md
  CONTRIBUTING.md
  TASKS.md
```

## الجودة والقبول

راجع `docs/TEST_PLAN.md`. على الأقل:
- unit tests لـ scope matching (including deceptive suffixes, wildcards, IDNA, IPv6, redirects).
- property/fuzz tests لمحلل URLs/headers، وfile-size/input validation.
- adapter contract tests باستخدام fake executables؛ لا تحتاج الإنترنت.
- tests لـ jobs/cancellation/retry/crash recovery.
- tests لـ redaction، API key storage abstraction، prompt injection، output schema validation.
- integration tests على local mock HTTP server ومختبر Juice Shop/crAPI اختياريًا.
- UI tests للمسارات الأساسية وعدم وجود زر غير عامل.
- build checks للـ frontend وPython engine وRust/Tauri.
- SAST/dependency audit وsecret scanning في CI.

## شروط الإصدار

- Linux x86_64 أولًا: بناء AppImage و`.deb` حيث أمكن، مع توثيق المكتبات runtime المطلوبة. اختبر على تثبيت نظيف/بيئة نظيفة. لا تدّعِ دعم كل توزيعات Linux من اختبار Ubuntu فقط.
- أضف ARM64 بعد CI واختبارات حقيقية. Windows/macOS أهداف مستقبلية إلا إذا بنيت واختبرت كل منصة.
- GitHub Actions للـ lint, typecheck, unit/integration tests, build. Release workflow يعمل على version tag فقط ويحمّل artifacts بلا أسرار.
- SBOM أو dependency/license inventory، third-party notices، checksum للـ release assets، ونسخة changelog.
- قبل الإعلان عن الجاهزية، اكتب ما اجتاز وما لم يجتز. لا تصف المنتج بأنه production-ready إذا كانت أي ميزة أساسية mock أو غير مختبرة.

## سير التنفيذ المطلوب

نفّذ مراحل `prompts/PHASE_01_CORE.md` إلى `PHASE_05_RELEASE.md` بالترتيب، ولا تتوقف بعد كل مرحلة لطلب إذن. بعد كل مرحلة شغّل الاختبارات واكتب نتائجها في `TASKS.md` و`docs/TEST_RESULTS.md`. استخدم `BLOCKED` فقط عند blocker حقيقي مع بديل آمن موضح.

## تسليم نهائي

في النهاية أعطني:
1. ملخص ما تم بناؤه فعلًا.
2. بنية المجلدات والوظائف الأساسية.
3. أوامر التشغيل والتثبيت والبناء على Linux.
4. الاختبارات المنفذة مع pass/fail والأوامر.
5. أي قيود أو أجزاء غير مكتملة بوضوح.
6. خطوات إنشاء GitHub repo وعمل أول release.
