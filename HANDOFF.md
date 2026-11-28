# Handoff: design workstream and the Supabase migration

For the chat or contributor working on `supabase-migration`. The design workstream (bugu redesign) and the migration both edit `index.html`, so this file is the meeting point. **Read it before you merge, and add a message at the bottom if you need something from design.**

Source of truth for the look: `DESIGN.md`. Rules for everyone: `AGENTS.md`.

## 1. What design has done so far (all merged to `main`)

| PR | Change | Touches script? |
|---|---|---|
| 1 | `DESIGN.md`, `AGENTS.md`, reference prototypes | no |
| 2 | Token layer: palette, Inter font, neutral status colours | **colour literals only**: 81 hard-coded hex colours became `var(--...)`, of which **15 lines are inside script template strings** (inline `style="..."`). No logic changed. |
| 3 | Shell: header wordmark, bottom tab bar, SVG icons | no |
| 4 | Home and listing rows (CSS only) | no |
| 5 | Listing detail (CSS only) | no |
| 6 | Sell flow (static markup and CSS) | no |
| 7 | Order and escrow modals (static markup and CSS) | no |
| 8 | Chats | no |
| 10 | This file | no |
| 11 | Splash, sign-in, register, wanted, notifications, reader; **BookWorm renamed to bugu in static markup**; `icons/` and manifest | no |
| 9 | Profile and dark mode switch | **adds** one tiny `<script>` in `<head>` (applies saved theme) and one `onclick` on `#themeSwitch`. No existing script was edited. |

PRs 3 to 11 were each checked by script: all element ids, all `onclick` handlers and all existing `<script>` blocks were identical to `main` before the PR (PR 9 adds one head script and one `onclick`). PR 2 is the exception described in its row: colour literals inside script template strings. That is the only reason a design change is visible in a `<script>` diff.

## 2. Known merge conflict with `supabase-migration` (stage 1)

Merging current `main` into `supabase-migration` gives **one** conflict, in the seller earnings box on the upload screen:

- design side (PR 2): colour `#3b82f6` became `var(--info)`
- your side: the delivery-fee note text changed

Resolution (keep your wording, keep the design token):

```html
<div style="font-size:11px;color:var(--info);margin-top:6px;">Note: the delivery fee is paid by the buyer on top of the book price and is not part of your earnings.</div>
```

Your `js-delivery-fee` span in `#pbDeliveryRow` merges cleanly.

## 3. Contract: please do not rename these

Design CSS targets these classes and ids. You can change what the script puts inside them, but please keep the names, or tell design when you rename:

- Listings: `.book-card`, `.book-card-img`, `.book-card-body`, `.book-card-meta`, `.book-card-title`, `.book-card-footer`, `.price`, `.badge-pill`, `.condition-new|good|used`, `.type-digital`, `.featured-badge`, `#booksGrid`
- Detail: `.detail-container`, `.detail-photo-main`, `.detail-photo-thumb`, `.detail-title`, `.detail-meta`, `.meta-tag`, `.detail-price`, `.price-breakdown`, `.price-breakdown-row` (with `.total`), `.seller-card`, `.seller-avatar`, `#detailActions`
- Chats: `.chat-item`, `.chat-avatar`, `.message.sent`, `.message.received`, `.chat-messages`, `.chat-input`, `.chat-send`
- Modals and order: `.modal-overlay` (toggled with `.active`), `.modal`, `.modal-close`, `.code-display`, `.code-number`, `.delivery-option`, `.tracking-card`, `.step-item`
- Profile: `.stat-card`, `.section-block`, `#themeSwitch`
- Shell: `nav`, `.nav-logo`, `.nav-btn`, `.nav-icon-btn`, `.badge`, `.bottom-nav`, `.bottom-nav-item`

## 4. Rules for new or changed UI code in the script

- Colours: use the tokens (`var(--ink)`, `var(--mute)`, `var(--line)`, `var(--surf)`, `var(--tint)`, `var(--bg)`, `var(--inv)`). **No new hex colours, and no red/green/blue/amber.** Status is shown with fill, outline and weight.
- No emoji in new UI strings. Use sentence case ("Add tracking number", not "Add Tracking Number").
- No new inline `font-weight:900` or `font-family`. Inter is the font.

## 5. What design will do after your migration merges (please tell us when)

1. **Emoji sweep in script templates:** card renderer (📚 📖 ⭐ ⏳), detail meta (📚 📖 🎓 📍), price breakdown title (💰), owner buttons (🗑️ ⭐ 📦 🔐 ✅), wanted board (✅ 📣 🔍), empty states, upload status text.
2. **Typographic covers:** a small change to the card template so a photo-less listing shows its real title on the cover.
3. **Rename BookWorm to bugu inside scripts.** The static markup, title, manifest and icons were renamed in PR 11. What remains is user-facing text built in scripts (messages, notifications, emails if any). Search for `BookWorm` inside `<script>`.
4. **One repo, two subdomains** (`app.` and `admin.`): after migration, and after the owner connects the domains.

Not before then, to avoid conflicts. If you rewrite any of the templates listed in 1 and 2 anyway, feel free to apply these rules yourself and say so below.

## 6. Notes for your side of the migration (not design work, but relevant)

- Supabase Auth: once the subdomains are connected, add them to the allowed redirect URLs and the site URL.
- The admin page decides who is an admin in the browser. With Supabase, real protection must come from **row-level security policies** that check the admin role server-side.

## 7. Messages

Add dated messages below. Design reads this file at the start of each session.

- _(design, 2026-11-28)_ Opened this file. Nothing needed from you yet apart from reading section 2 before merging.

- _(design, 2026-11-28)_ Correction to section 1: PR 2 did change 15 script lines (colour literals inside style strings only). Admin repo: see its `HANDOFF.md`.
