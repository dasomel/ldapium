# Group pagination — 2026-10-02

User requested paging in Groups. Scope: GroupsPage, small GroupPagination footer,
EN/KO navigation label and browser regression. Preserve LDAP API, group CRUD,
membership and existing response-cap warning. Client-side pagination matches the
Users list's current architecture; no LDAP schema/auth/backend changes.

Acceptance: 10/20/50/100 choices, page numbers, first/previous/next/last controls;
search and size reset page 1; visible-row keyboard editing; last page disabled and
bounded if data shrinks; empty search and 390px layout usable.

Evidence: lint/build passed (existing warnings); independent static review PASS.
5173 browser test: 1 passed (1.9s); rebuilt 8080: 1 passed (1.3s). Test covers 23 items, first/last boundaries,
visible-row editing, search reset, size reset, no results, mobile width and zero
mutation requests. Local 8080 rebuilt/restarted with existing feature menus.
Preserved failures: initial npm run used repo root (corrected to frontend cwd);
row Enter opened and immediately submitted dialog (preventDefault added); select
name included option text (explicit aria-label added). Relevant checks rerun.

Static review: /tmp/ldapium-group-pagination-review.txt. UI paging operates only
on fetched entries; server truncation remains a limit. No commits or pushes.
