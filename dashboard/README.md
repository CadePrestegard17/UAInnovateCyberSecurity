# Hackathon Security Dashboard

A React + Vite + TypeScript SOC dashboard that loads auth, DNS, firewall, and malware CSV logs from `/public/data` (or user uploads), runs correlation rules, and visualizes incidents. No backend required. Single-page app with no client-side routing.

## Run locally

1. Install dependencies:
   ```bash
   npm install
   ```

2. Start the dev server:
   ```bash
   npm run dev
   ```

3. Open [http://localhost:5173](http://localhost:5173). The app fetches CSV files from `/data/` (served from `public/data/`) or you can upload your own.

## Deploy to Vercel (free) — exact steps

1. **Push to GitHub**  
   Create a repository and push this project. If the app lives in a subfolder (e.g. `dashboard`), the repo can contain just that folder or the whole monorepo.

2. **Import to Vercel**  
   Go to [vercel.com](https://vercel.com), sign in with GitHub, then click **Add New…** → **Project**. Select your GitHub repo. If the app is in a subfolder, set **Root Directory** to that folder (e.g. `dashboard`) and click **Edit** next to it to confirm.

3. **Framework preset: Vite**  
   Leave **Framework Preset** as **Vite** (Vercel usually detects it).

4. **Build command:** `npm run build`  
   Set **Build Command** to `npm run build`.

5. **Output directory:** `dist`  
   Set **Output Directory** to `dist`.

6. **Confirm deployment URL**  
   Click **Deploy**. When the build finishes, Vercel shows the deployment URL (e.g. `https://your-project.vercel.app`). Open it to confirm the dashboard loads. Bundled CSV data is served from `/data/*.csv` from the `dist` output.

**Notes:** No environment variables are required. The repo’s `vercel.json` adds a rewrite so the single-page app is served for all paths; static assets and `/data/` files are still served correctly.

## Scripts

- `npm run dev` — start dev server
- `npm run build` — typecheck and production build (output in `dist/`)
- `npm run preview` — serve the production build locally
- `npm run lint` — run ESLint

## Data

CSV files in `public/data/` are copied to `dist/data/` on build and loaded at runtime via `fetch('/data/<filename>.csv')`. Users can also upload their own CSVs in the app.
