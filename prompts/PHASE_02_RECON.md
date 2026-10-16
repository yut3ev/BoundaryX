# Phase 02 — Recon, Adapters & Jobs

اقرأ `docs/INTEGRATIONS.md`, `config/tool-manifest.yaml`, `docs/THREAT_MODEL.md`.

نفّذ:
- `ToolAdapter` contract موحد (detect/version/validate_config/build_argv/run/parse/health_check/cancel).
- registry للأدوات بحالات installed/missing/incompatible/error، والامتناع عن الادعاء بأن أداة مثبتة ما لم يتم التحقق.
- subprocess execution بوسائط argv وليس shell string، timeouts، output cap، env sanitization، process-group cancellation، cleanup.
- job queue بحالاتها المحددة وسجل أحداث قابل للمراجعة. دعم pause/cancel بقدر الإمكان وinterrupted recovery.
- أول integrations حسب manifest، passive أولًا ثم active opt-in مع rate limits scope guard لكل target/redirect.
- normalized assets schema وتوحيد duplicate records مع حفظ provenance/raw reference.
- import CSV/JSON/HAR/OpenAPI بصيغ موثقة وحجم محدود وتنقيح أسرار.
- asset diff بين جولات حقيقية.

لا تشغّل أدوات ضد أهداف عامة في اختبارات CI. استخدم fake executables وlocal mock server.

معايير الخروج: يمكن إدخال بيانات/تشغيل adapter أو import، ورؤية النتائج الفعلية مرتبطة بـ job وأصلها. اختبار إلغاء job، timeout، الأداة المفقودة، scope denial، malformed output، وredaction.
