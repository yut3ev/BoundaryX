# Phase 01 — Core Foundation

اقرأ `AGENT_RULES.md`, `docs/PRODUCT_SPEC.md`, `docs/ARCHITECTURE.md`, `docs/DATA_MODEL.md`, `docs/UI_UX.md`.

نفّذ الأساس الفعلي:
- scaffold Tauri 2 + React + TypeScript + Python engine managed by uv.
- SQLite schema/migrations/repository layer مع foreign keys وtransactions.
- navigation and layouts لكل الأقسام المطلوبة، مع empty/error/loading states حقيقية.
- Projects & Scope CRUD مع backend scope validator واختبارات الحدود.
- IPC command/event contracts؛ لا تُنشئ HTTP server مكشوفًا.
- config loading، app data dirs، rotating logs with redaction، graceful shutdown.
- `.env.example`, `.gitignore`, scripts للـ dev/test/build، و`TASKS.md`.
- استبدل أي placeholder ببيانات واضحة أنها empty/demo، ولا تضع dashboards بأرقام ثابتة.

معايير الخروج:
- يمكن تشغيل التطبيق محليًا، إنشاء workspace وإضافة rules/exclusions، إغلاقه وفتحه وتبقى البيانات.
- اختبارات scope تشمل suffix spoofing وwildcards والـ redirects.
- تشغيل frontend lint/typecheck وPython tests وRust/Tauri checks.
- سجّل commands ونتائجها الفعلية في `docs/TEST_RESULTS.md`.
