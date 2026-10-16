# Phase 04 — Findings, Evidence & Reports

نفّذ نموذج Findings الموجود في `docs/DATA_MODEL.md` وربطه بالـ jobs/assets/evidence. لا تعتمد على static seed data لإظهار نجاح الميزة.

المطلوب:
- state machine: candidate → needs_review → verified/false_positive/accepted_risk → fixed/reopened حسب الانتقالات المسموحة.
- candidate لا يتحول إلى verified آليًا لمجرد finding output من scanner. اجعل التحقق action واضحًا يسجل المستخدم/الدليل وطريقة التحقق.
- dedup suggestions دون دمج نهائي تلقائي؛ evidence linking؛ confidence منفصل عن severity.
- evidence viewer مع redaction وraw original محفوظ فقط حسب اختيار المستخدم وبصلاحيات ملفات محلية مناسبة.
- report templates Markdown/HTML وJSON/CSV export sanitized؛ توليد التقرير لا يرفع البيانات لأي خدمة خارجية.
- export/import round-trip، migrations upgrade tests، duplicate finding scenarios، report escaping لمنع HTML injection.
- UI: filters, search, details drawer/page, evidence tab, notes, report preview, export validation.

معايير الخروج: يمكن أخذ job results أو import من fixture إلى candidate، مراجعتها ثم إنشاء report به أدلة حقيقية من fixture/محاكاة أو target مصرح به. التقرير يميز actual/expected ويخفي tokens/cookies.
