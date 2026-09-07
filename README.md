# AI Website Auditor

A Streamlit website-audit application that accepts a public website URL and produces:

- SEO checks
- Google PageSpeed performance score and key Lighthouse audits
- Accessibility score
- Best-practices score
- Passive security configuration checks
- HTTPS/TLS information
- Security-header checks
- Cookie flag checks
- robots.txt / sitemap.xml discovery
- HTML/technical checks
- Gemini-generated professional audit report

## Important security scope

This is a **passive/non-intrusive auditor**. It does not exploit vulnerabilities, brute-force endpoints, upload payloads, bypass authentication, or run destructive penetration tests.

Security findings such as a missing CSP or HSTS header are configuration findings, not proof that a website is exploitable.

## 1. Install

```bash
pip install -r requirements.txt
```

## 2. Add Gemini API key

For local development create:

`.streamlit/secrets.toml`

```toml
GEMINI_API_KEY = "YOUR_GEMINI_API_KEY"
```

Do not commit this file to GitHub.

The app uses Google's current `google-genai` SDK and Gemini model for the AI report.

## 3. Run

```bash
streamlit run app.py
```

## 4. Deploy to Streamlit Community Cloud

1. Push this project to GitHub.
2. Open Streamlit Community Cloud.
3. Select the GitHub repository and `app.py`.
4. In the app's Secrets settings add:

```toml
GEMINI_API_KEY = "YOUR_GEMINI_API_KEY"
```

5. Deploy.

## Architecture

Website URL
→ HTTP fetch
→ HTML/SEO analyzer
→ passive security analyzer
→ robots/sitemap checks
→ Google PageSpeed Insights
→ Gemini analysis
→ Streamlit report

## Limitations

- PageSpeed/Lighthouse results can vary between runs.
- Some sites block automated requests or require JavaScript rendering.
- This version analyzes the initial HTML response and PageSpeed results; it is not a full browser crawler.
- It does not test authenticated pages.
- It does not replace a professional penetration test.
