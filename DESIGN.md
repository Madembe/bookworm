# bugu design system

> **Source of truth for the look, feel and structure of bugu (formerly BookWorm).**
> Every change to UI in this repo, by a person or an AI session, must follow this file.
> If you want to change a decision here, open a PR that edits this file first and get the owner's approval. Do not quietly restyle screens.

Reference prototypes (approved by the owner) live in `design/reference/`. Open them in a browser to see the target.

## 1. Goal

bugu is a textbook marketplace for South African students. The design must be **simple but never mediocre**, and a student should **fall in love at first glance**.

It should feel like a calm, intelligent study tool. It must **not** feel like a fashion or clothing store (no huge italic serif headlines, no lookbook grids, no floating pill menus).

## 2. Name and logo

- Name: **bugu** (TshiVenda for "book"). Always lowercase in the wordmark.
- Mark: a small page split down the middle, half filled, half outline. Wordmark: Inter 600, tight tracking (-0.035em).
- App icon: a lowercase **b**. It works best in dark mode (light letter on near-black).
- Pronunciation note to show once on the splash or sign-up screen: "bugu: Tshivenda for book".
- Status: the owner chose the name. Availability still needs checking (CIPC, Google Play, App Store, .co.za, social handles). Until the rename PR, code, package names and repo names may still say BookWorm.

## 3. Colour: black and white only, dimmed

Strictly neutral greys. No warm tint, no brand colour, no pure `#000` or `#fff` (too harsh on the eyes). Meaning is carried by fill, outline and weight, never by hue.

| Token | Light | Dark | Use |
|---|---|---|---|
| `--bg` | `#e6e6e5` | `#171717` | page background |
| `--surf` | `#efefee` | `#1f1f1f` | cards, inputs, bars |
| `--ink` | `#222222` | `#d6d6d4` | text, primary buttons |
| `--mute` | `#6b6b6b` | `#8b8b8a` | secondary text |
| `--line` | `#cfcfcd` | `#2d2d2d` | borders, dividers |
| `--inv` | `#e6e6e5` | `#171717` | text on `--ink` |

Dark mode follows the system setting and can be toggled in Profile.

Do not add colour (including success, error and warning colours) without the owner's approval. Status is shown with pills: outline = neutral, bold outline = in progress, filled = needs attention.

## 4. Type

- **Inter** (400, 500, 600) for all UI. Headlines are 600, tight tracking, normal case.
- **IBM Plex Mono** (500) for module codes and order numbers, e.g. `ACCN101`.
- **Source Serif 4** (600) only on generated book covers.
- Banned: Nunito 900 headlines, emoji as icons, big italic serif display type.

## 5. Shape and spacing

- Radius: 10px controls, 12px cards, 8px chips, 2px/5px on book covers (spine side square), pills only for status.
- App content max-width 560px. Admin max-width 1180px.
- Borders are 1px `--line`. Shadows only on book covers and the mobile admin drawer.
- Icons: inline SVG, 1.6px stroke, rounded caps, 18 to 22px. No emoji anywhere in UI.

## 6. Core components

- **Book cover:** typographic cover (module code, serif title, rule) with a spine shade. Alternates dark and light. Real photos replace it when available.
- **Listing row:** cover on the left; module code and campus in mono, title, edition and seller, price (600) and a condition tag. A listing is a catalogue row, not a product-grid tile.
- **Search:** one field, placeholder "Module code or title, e.g. ACCN101".
- **Chips:** campuses and conditions. Selected chip is filled `--ink`.
- **Escrow strip:** one slim line under search: "Pay safely. Money is held until you confirm the book."
- **Bottom tab bar:** full width, labelled: Home, Sell, Chats, Profile.
- **Buttons:** primary filled `--ink`, secondary outline. 50px tall in the app, 38px in admin.
- **Timeline:** used for orders and disputes. Done = filled dot, now = ringed dot, next = empty dot.

## 7. Screens (app)

Home, Listing detail (sticky buy bar), Order/escrow (timeline, "I have the book, release payment", "Something is wrong"), Sell (one short form, price hint from similar listings), Chats (list and room with the book pinned), Profile (stats, menu, dark mode switch). Auth, Wanted, Notifications and the digital reader must be restyled with the same components.

## 8. Admin

- Grouped sidebar instead of 24 flat pages:
  - **Overview:** Dashboard
  - **Money:** Transactions, Disputes, Payouts, Deliveries
  - **Marketplace:** Listings, Digital books, Wanted, Flagged, Chats
  - **People:** Users, Ambassadors, Team
  - **Support:** Support, AI support, Feedback, Escalations
  - **Growth:** Promotions, Reports
  - **System:** Health, System status, Audit log, Settings, Status preview
- Dashboard opens on **needs attention** (disputes, payouts to approve, flagged listings, support tickets), each card opens its queue.
- Dispute view shows the timeline and the three decisions: refund buyer, pay seller, ask for evidence.
- Must work on a phone: sidebar becomes a drawer under 900px, tables scroll sideways.

## 9. Voice

Plain, calm, short. Say what happens to the money. No hype, no exclamation marks, no emoji.

## 10. Rules for contributors and AI sessions

1. Read this file before touching any UI.
2. **Never push to `main` and never merge.** Work on a branch and open a PR. The owner merges.
3. Design PRs change look and structure only. Do not change business logic, data, auth, or payment behaviour (for example `create-payment.js`) in a design PR. The backend is being moved from Firebase to Supabase in a separate workstream, so **keep every element `id`, `name` and `onclick`/handler function name unchanged** when restyling markup, and never edit the `<script>` data and auth code.
4. Do not invent business rules (fees, limits, policies) in the UI. Show only what the system really does.
5. Keep PRs small: one screen or one concern each, and describe what changed.
6. If something here conflicts with a request, flag it in the PR rather than overriding it.

## 11. Rollout (one PR per step)

1. Design contract and reference prototypes (this PR).
2. Token layer: replace colours and fonts with the tokens above; no layout changes.
3. Shell: header, bottom tab bar, icons replacing emoji.
4. Home and listing rows. 5. Listing detail. 6. Sell flow. 7. Order/escrow. 8. Chats. 9. Profile. 10. Auth, Wanted, Notifications, Reader.
11. Admin: shell and grouped navigation, then dashboard, disputes, transactions, remaining pages.
12. Rename BookWorm to bugu in titles, manifest and icons, once the name is cleared.

## 12. Open decisions

- Name availability checks (section 2).
- Final logo artwork and the app icon file.
- Whether any functional colour (for example for errors) is ever allowed.
