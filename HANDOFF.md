# Handoff: design workstream and the Supabase migration (admin)

For the chat or contributor migrating the admin to Supabase. The admin is one `index.html`, so design and migration will both edit it. **Read this before merging and add a message at the bottom if you need something from design.**

Source of truth for the look: `DESIGN.md`. Rules for everyone: `AGENTS.md`. The same arrangement is in the web repo (`HANDOFF.md` there lists the web app's contract and a known conflict).

## Contract (admin)

- Design PRs change CSS and static markup only. Every element `id`, every `onclick`/`onchange`/`oninput` handler name and every existing `<script>` block must stay byte-identical. Each design PR is checked by script for this.
- Page switching (`showPage` or equivalent) and the ids of page containers (`page-*`) are relied on by the new grouped navigation. Please do not rename them, or tell design.
- Colours: tokens only (`var(--ink)`, `var(--mute)`, `var(--line)`, `var(--surf)`, `var(--tint)`, `var(--bg)`, `var(--inv)`). No new hex colours. No emoji in new UI strings.
- Admin authorization must be enforced server-side (Supabase RLS policies that check the admin role), not only by a browser check.

## After your migration merges

Design will: sweep emoji from script templates, rename BookWorm to bugu, and move the admin into the shared repo as `admin.bugu.co.za` (owner connects domains later). Please tell us here when the admin migration has merged.

## Messages

- _(design, 2026-11-28)_ Opened this file.
