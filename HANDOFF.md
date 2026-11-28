# Handoff: design workstream and the Supabase migration (admin)

For the chat or contributor migrating the admin to Supabase. The admin is one `index.html`, so design and migration will both edit it. **Read this before merging and add a message at the bottom if you need something from design.**

Source of truth for the look: `DESIGN.md`. Rules for everyone: `AGENTS.md`. The same arrangement is in the web repo (`HANDOFF.md` there lists the web app's contract and a known conflict).

## Contract (admin)

- Design PRs change CSS and static markup. Every element `id` and every `onclick`/`onchange`/`oninput` handler name must stay the same. Existing `<script>` blocks stay byte-identical **except colour literals inside inline style strings**, which become tokens (admin PR 3 changed 5 such lines: a sold/pending notice and the payouts list). Each design PR is checked by script for this.
- Page switching (`showPage` or equivalent) and the ids of page containers (`page-*`) are relied on by the new grouped navigation. Please do not rename them, or tell design.
- Colours: tokens only (`var(--ink)`, `var(--mute)`, `var(--line)`, `var(--surf)`, `var(--tint)`, `var(--bg)`, `var(--inv)`). No new hex colours. No emoji in new UI strings.
- Admin authorization must be enforced server-side (Supabase RLS policies that check the admin role), not only by a browser check.

## What design has done (admin)

- PR 1: design contract and reference prototype (merged).
- PR 3 (open): tokens, grouped sidebar (7 groups, same `showPage(...)` handlers, `.nav-item` only toggles `active`), wordmark, status pills without colour, mobile drawer, dark mode switch, 124 emoji removed from static markup.

## Still to do after your migration merges

- "Needs attention" dashboard cards and the dispute decision panel (need script changes).
- Emoji sweep in script templates (tables, buttons, toasts) and `BookWorm` text inside scripts.
- Status tags: the script emits classes like `tag-open`, `tag-pending`, `tag-failed`. Design CSS maps them to filled, bold outline and quiet outline. Keep using those class names.

## After your migration merges

Design will: sweep emoji from script templates, rename BookWorm to bugu, and move the admin into the shared repo as `admin.bugu.co.za` (owner connects domains later). Please tell us here when the admin migration has merged.

## Messages

- _(design, 2026-11-28)_ Opened this file.
