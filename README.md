# bugu

Student textbook marketplace for South Africa. One repo, two sites, one Vercel project.

| Folder | What | Host (when connected) |
|---|---|---|
| `app/` | The student app (`index.html`, manifest, icons) | `app.bugu.co.za` |
| `admin/` | The admin console (`index.html`) | `admin.bugu.co.za` |
| `api/` | Serverless functions shared by both: PayFast signing and webhook, admin user creation | both, at `/api/...` |
| `shared/` | `tokens.css`: the design tokens used by both sites | both, at `/shared/tokens.css` |
| `design/reference/` | Approved prototypes (sample data, not production) | n/a |

`vercel.json` routes by hostname: `admin.bugu.co.za` serves `admin/`, every other host serves `app/`. `/api` and `/shared` are the same on both. Opening `/admin/` on the app host (or `/app/` on the admin host) redirects to `/`.

Backend: Supabase (auth, database, realtime). Payments: PayFast. Read `DESIGN.md` before changing any UI, and `HANDOFF.md` and `AGENTS.md` for how contributors and AI sessions work in this repo.

## Environment variables (Vercel project settings)

`SUPABASE_URL`, `SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_ROLE_KEY`, `PAYFAST_MERCHANT_ID`, `PAYFAST_MERCHANT_KEY`, `PAYFAST_PASSPHRASE`, `PAYFAST_SANDBOX`, `SITE_URL` (the app's public URL, for PayFast return and notify links).

## Connecting the domains (not done yet)

1. In Vercel, add `app.bugu.co.za` and `admin.bugu.co.za` to this one project and create the DNS records Vercel shows.
2. Set `SITE_URL` to `https://app.bugu.co.za`.
3. In Supabase Auth, set the site URL to `https://app.bugu.co.za` and add both subdomains to the allowed redirect URLs.
4. Update the PayFast return, cancel and notify URLs to the app domain.
5. Test on the preview first. Then retire the old separate admin project.

The routing for the two hosts only takes effect once the domains are attached. Until then every preview and `*.vercel.app` URL serves the app, and the admin is reachable at `/admin/` on previews.

## Run locally

`npx vercel dev` from the repo root (needs the environment variables above).
