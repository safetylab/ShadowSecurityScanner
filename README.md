# website/ — public landing page & SEO/AEO assets

Static, self-contained marketing + discoverability site for ShadowSecurityScanner.
No build step; plain HTML/CSS/SVG. Canonical URL:
`https://shadowsecurityscanner.com/` (custom domain; the github.io Pages deploy
is a mirror). SEO tags (canonical/OG/sitemap/llms) point at the apex domain.

## Files
- `index.html` — landing page. Semantic HTML, meta description, Open Graph &
  Twitter cards, canonical, and two JSON-LD blocks (`SoftwareApplication` +
  `FAQPage`). Keyword-targeted for "network vulnerability scanner", "free /
  self-hosted", "Nessus / OpenVAS alternative", "agentless CVE scanner".
- `llms.txt` — structured summary for AI / answer-engine crawlers (llmstxt.org).
- `robots.txt`, `sitemap.xml` — crawler directives + sitemap.
- `og-image.svg`, `favicon.svg` — social share image and icon.
- `README-public.md` — SEO-optimized README to copy into the **public** repo
  (`safetylab/ShadowSecurityScanner`), whose README is what search engines and
  AI assistants actually index.

## Deploy
GitHub Pages for the public repo is served from its `gh-pages` branch, which the
`audit-feed` workflow force-pushes from its built `public/` directory. This
workflow copies `website/` into `public/` before that push, so `gh-pages` serves
**both** the landing page (`index.html` at root) and the JSON feed
(`catalog-manifest.json`, `*.json.gz`). No separate deploy needed; the site
publishes on the next audit-feed run. Verify with a real CI run — the deploy
uses the `FEED_DEPLOY_KEY` secret and cannot be tested locally.

## Recommended follow-ups
The canonical site now lives at the apex domain `https://shadowsecurityscanner.com/`,
so `robots.txt` / `llms.txt` are authoritative at the root (the earlier
github.io project-subpath limitation no longer applies to the canonical site).
To maximize reach:

1. **OG image format** — `og-image.svg` renders in Google but many social
   scrapers (Slack, X/Twitter, LinkedIn, Facebook) require PNG/JPG. Generate a
   1200×630 PNG and point `og:image`/`twitter:image` at it, e.g.
   `rsvg-convert -w 1200 -h 630 og-image.svg -o og-image.png` (or any SVG→PNG).
2. **Submit the sitemap** to Google Search Console and Bing Webmaster Tools, and
   request indexing of the URL.
3. **Public repo metadata** (highest-leverage, do in the GitHub UI on
   `safetylab/ShadowSecurityScanner`):
   - Replace the README with `README-public.md`.
   - Set the repo **description**: *"Free, self-hosted network vulnerability
     scanner — agentless CVE detection with CISA KEV & EPSS prioritization. A
     Nessus/OpenVAS alternative for Windows, Linux and macOS."*
   - Add **topics**: `vulnerability-scanner`, `security`, `cve`, `network-scanner`,
     `nessus-alternative`, `openvas-alternative`, `infosec`, `pentesting`,
     `security-tools`, `kev`, `epss`, `self-hosted`, `agentless`, `sbom`.
   - Set the repo **homepage** to `https://shadowsecurityscanner.com/`.
4. **Off-page (not code)** — ranking "at the top" also needs backlinks, real
   traffic and mentions: submit to tool directories (AlternativeTo, Awesome
   Security lists, Product Hunt), and answer relevant questions where the tool
   genuinely fits. Code can't manufacture these.

## Accuracy note
The source repo is private; only binaries are public (MIT-licensed). Copy
therefore says "free / self-hosted", not "open source". If the source becomes
public, add the high-value "open source vulnerability scanner" phrasing to
`index.html`, `llms.txt` and `README-public.md`.
