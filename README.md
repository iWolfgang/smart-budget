# Startup Funds Hub

A single-file, local-first web app to track and budget your startup's funds. All data is **end-to-end encrypted in your browser** with AES-256-GCM — there's no backend, no analytics, no cloud sync.

Live demo: _set this once GitHub Pages is enabled_ (see [Deploy](#deploy)).

## Features

- **Dashboard** — total raised, total spent, cash remaining, average monthly burn, runway in months
- **Transactions** — debit/credit entries with categories, descriptions, search, filter by date/type/category, running balance
- **Budget vs Actual** — set a budget per category, see variance and progress bars (all-time / current month / YTD)
- **Categories** — 10 sensible defaults (Salaries, R&D, Cloud, Marketing, Office, Legal, Travel, Equipment, Misc, Funding) plus custom categories
- **Charts** — cash balance over time, spending by category, monthly inflows vs outflows
- **Multi-currency** — CNY (¥), USD, EUR, GBP, HKD, JPY
- **Light / Dark / System theme** with live OS-appearance tracking
- **Encrypted storage** — username + password gates the app; PBKDF2-SHA256 (200k iterations) + AES-256-GCM
- **Backup** — export/import JSON, export CSV
- **Sample data** for a quick tour

## Tech

Plain HTML, CSS, and vanilla JavaScript. Two external dependencies, both loaded from a public CDN with [Subresource Integrity](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity) pinning:

- [Chart.js 4.4.1](https://www.chartjs.org/) — charts
- The browser's built-in [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) — PBKDF2 + AES-GCM

No build step. No package.json. The entire app is a single `index.html` file.

## Security model

Your transactions, categories, budgets, and settings are stored in the browser's `localStorage` as ciphertext. The encryption key is derived from your password with PBKDF2 (SHA-256, 200,000 iterations, random per-account salt) and held only in memory while you're signed in. A wrong password fails the AES-GCM authentication tag and the app refuses to load the data — there's no backdoor.

**If you forget your password, your data is unrecoverable.** Use the **Export JSON** button regularly to keep an off-app backup. Note: exported JSON is plaintext — protect that file with normal file-level security.

The Web Crypto API requires a [secure context](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts), which means the app must be served over HTTPS (or `localhost`, or `file://`). GitHub Pages provides HTTPS automatically.

## Run locally

Just open `index.html` in any modern browser. No server needed.

```bash
# macOS
open index.html
```

You can also serve the folder with any static server, e.g.:

```bash
python3 -m http.server 8000
# then visit http://localhost:8000
```

## Deploy to GitHub Pages

1. **Create a new repository** on [github.com/new](https://github.com/new) — for example `smart-budget`. Leave it empty (no README, no .gitignore).
2. **Push this folder:**
   ```bash
   git remote add origin git@github.com:<your-username>/smart-budget.git
   git push -u origin main
   ```
3. **Enable Pages:** in your repo, go to **Settings → Pages**, set **Source: Deploy from a branch**, **Branch: `main` / `/ (root)`**, and **Save**.
4. After ~1 minute, your site is live at `https://<your-username>.github.io/smart-budget/`.

That's it. No build pipeline, no Actions workflow needed.

### Custom domain (optional)

Add a `CNAME` file at the repo root containing your domain, then point a CNAME DNS record at `<your-username>.github.io`. GitHub Pages will provision a Let's Encrypt cert automatically.

## Deploy elsewhere

Any static host works — Cloudflare Pages, Netlify, Vercel, Nginx on a VPS, S3 + CloudFront, etc. The only requirement is **HTTPS** (Web Crypto API needs it).

## Migrating data between origins

`localStorage` is scoped per-origin, so data on `file://` is separate from your live `*.github.io` site. To carry over your transactions:

1. On the source origin: **Settings → Backup & restore → Export JSON**.
2. On the destination: complete account setup, then **Settings → Backup & restore → Import JSON**.

## License

[MIT](LICENSE)
