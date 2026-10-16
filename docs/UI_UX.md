# UI / UX Specification

## Visual direction

Professional security research desktop app: charcoal/near-black surfaces, restrained cyan/blue accent, readable typography, clear severity colors used sparingly, meaningful whitespace. Avoid neon overload, hacker movie visuals, gratuitous animation, decorative terminal spam and “AI-generated template” appearance.

## Shell layout

- Left sidebar with workspace/program selector and primary navigation.
- Top bar: active program, global search, job indicator, notifications, settings.
- Main content: data-rich tables, filters, detail panels and split panes when helpful.
- Right detail drawer for asset/finding/evidence previews where space allows.
- Persistent job tray for queued/running/completed/failed jobs, cancellation and event stream.
- Desktop min window should be documented and app remain usable at narrower window size.

## Navigation

1. Overview
2. Programs & Scope
3. Assets
4. Recon Jobs
5. Traffic & API
6. Test Planner
7. Findings
8. Reports
9. Toolchain
10. Settings

## Key components

- Scope status as explicit `In scope`, `Out of scope`, `Unknown`, never color alone.
- Tables have sticky headers, sortable columns, saved filters when implemented, pagination/virtualization for large result sets.
- Search by host/path/title/tag/status; show query clear action and result count.
- Severity and confidence are separate fields.
- Evidence has provenance badges: manual, imported, tool, AI-generated suggestion.
- AI output is visually distinguished from verified observations and always provides linked evidence IDs.
- Active job review panel lists target count, in-scope check, tool/options, estimated request budget, active/passive classification, rate limit and stop action.
- Destructive actions require confirmation and make consequences explicit.

## States

Every page/major component must implement:
- Initial loading.
- Empty state with a useful next step (not a fake sample result).
- Success state with actual data.
- Partial state with warnings (for example, one optional tool missing).
- Error state with safe message and retry/recovery action.
- Offline/AI unavailable/tool unavailable states when relevant.

## Interaction quality

- Keyboard navigable; focus visible; labels/accessible names; contrast meets WCAG AA target where feasible.
- Avoid hover-only actions.
- Loading states never imply completion.
- Toasts are supplementary; errors are also visible in context.
- Job progress is based on real engine events, not invented percentage if the tool does not report it; otherwise show indeterminate progress.
- No modal for every tiny action; use confirmations where safety/privacy implications exist.

## RTL and localization

English first by default. Structure layout and CSS for future Arabic/RTL without hardcoded text widths or layout assumptions. Do not machine-translate technical identifiers. User-facing copy should be editable via localization files when practical.

## UX acceptance checklist

- No dead buttons or fake data.
- Each form validates and shows field-level errors.
- Search/filter state behaves correctly.
- Cancel button stops a real operation.
- Scope-denied operation explains why and does not send requests.
- Gemini sends nothing until the user accepts the selected context.
- Reports can be previewed and redaction verified before export.
