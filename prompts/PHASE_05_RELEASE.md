# Phase 05 — Linux Packaging, CI & Release Hardening

اقرأ `docs/LINUX_AND_RELEASE.md`, `docs/GITHUB_PROJECT.md`, `docs/TEST_PLAN.md`, `SECURITY.md`.

نفّذ release engineering:
- توثيق setup dev على Ubuntu/Debian، Fedora وArch حيث أمكن، مع التفريق بين build-time dependencies وruntime libraries.
- إعداد Tauri bundling، Linux x86_64 `.deb` وAppImage إذا كان عمليًا، والتحقق من تشغيل Python sidecar المعبأ. لا تذكر artifact دعمًا رسميًا ما لم يبنَ ويختبر فعليًا.
- GitHub Actions للـ frontend lint/typecheck/build، Python lint/typecheck/tests، Rust fmt/clippy/test، secret scan وdependency/license checks.
- Release workflow فقط على `v*` tags؛ لا تستخدم secrets غير ضرورية؛ لا ترفع مفاتيح أو ملفات user data. ارفق hashes وchangelog وthird-party license inventory.
- `README.md` root للمشروع، `CONTRIBUTING.md`, `SECURITY.md`, `LICENSE`, issue/PR templates، وGitHub release checklist.
- dependency locking والتحديث الآمن، SBOM (إن أمكن) وتوثيق known limitations.
- اختبر من checkout نظيف ثم build. اختبر artifact داخل VM/container مناسب أو جهاز Linux نظيف، وسجل المكتبات المطلوبة.

لا تتجاوز فشل build أو tests. لو تعذر target محدد، اكتب BLOCKED بوضوح ولا تدّعِ أن artifact جاهز.
