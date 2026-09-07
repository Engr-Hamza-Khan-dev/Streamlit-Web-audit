
import json
import re
import ssl
import socket
from datetime import datetime
from urllib.parse import urljoin, urlparse

import requests
import streamlit as st
from bs4 import BeautifulSoup
from google import genai

st.set_page_config(
    page_title="AI Website Auditor",
    page_icon="🔎",
    layout="wide",
)

USER_AGENT = "AI-Website-Auditor/1.0 (+passive-audit)"
TIMEOUT = 20

SECURITY_HEADERS = {
    "content-security-policy": "Helps control which resources a browser may execute/load.",
    "strict-transport-security": "Forces HTTPS in supporting browsers.",
    "x-content-type-options": "Reduces MIME-sniffing risks.",
    "x-frame-options": "Helps reduce clickjacking exposure.",
    "referrer-policy": "Controls referrer information sent to other sites.",
    "permissions-policy": "Restricts browser capabilities/features.",
}

def normalize_url(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("Please enter a website URL.")
    if not re.match(r"^https?://", value, re.I):
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("Enter a valid HTTP/HTTPS website URL.")
    return value

def fetch_page(url: str):
    headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"}
    response = requests.get(
        url, headers=headers, timeout=TIMEOUT, allow_redirects=True
    )
    response.raise_for_status()
    return response

def get_tls_info(hostname: str, port: int = 443):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls:
                cert = tls.getpeercert()
                return {
                    "tls_version": tls.version(),
                    "cipher": tls.cipher()[0] if tls.cipher() else None,
                    "certificate_subject": dict(x[0] for x in cert.get("subject", [])),
                    "certificate_issuer": dict(x[0] for x in cert.get("issuer", [])),
                }
    except Exception as exc:
        return {"error": str(exc)}

def analyze_html(url: str, response: requests.Response):
    soup = BeautifulSoup(response.text, "html.parser")
    parsed = urlparse(response.url)

    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    meta_desc = soup.find("meta", attrs={"name": re.compile("^description$", re.I)})
    canonical = soup.find("link", rel=lambda x: x and "canonical" in x)
    viewport = soup.find("meta", attrs={"name": re.compile("^viewport$", re.I)})

    headings = {}
    for level in range(1, 7):
        headings[f"h{level}"] = len(soup.find_all(f"h{level}"))

    images = soup.find_all("img")
    images_missing_alt = [
        (img.get("src") or "")[:200]
        for img in images
        if not img.get("alt", "").strip()
    ]

    links = soup.find_all("a", href=True)
    internal_links = 0
    external_links = 0
    for link in links:
        href = urljoin(response.url, link["href"])
        target = urlparse(href)
        if target.netloc and target.netloc == parsed.netloc:
            internal_links += 1
        elif target.netloc:
            external_links += 1

    scripts = soup.find_all("script", src=True)
    stylesheets = soup.find_all("link", href=True)
    forms = soup.find_all("form")

    mixed_content = []
    if parsed.scheme == "https":
        for tag in soup.find_all(src=True):
            src = urljoin(response.url, tag.get("src"))
            if src.lower().startswith("http://"):
                mixed_content.append(src[:250])
        for tag in soup.find_all(href=True):
            href = urljoin(response.url, tag.get("href"))
            if href.lower().startswith("http://"):
                mixed_content.append(href[:250])

    return {
        "final_url": response.url,
        "status_code": response.status_code,
        "content_type": response.headers.get("content-type", ""),
        "response_time_seconds": round(response.elapsed.total_seconds(), 3),
        "page_size_kb": round(len(response.content) / 1024, 2),
        "title": title,
        "title_length": len(title),
        "meta_description": meta_desc.get("content", "").strip() if meta_desc else "",
        "meta_description_length": len(meta_desc.get("content", "").strip()) if meta_desc else 0,
        "canonical": canonical.get("href", "").strip() if canonical else "",
        "viewport": viewport.get("content", "").strip() if viewport else "",
        "headings": headings,
        "images_total": len(images),
        "images_missing_alt": images_missing_alt[:50],
        "links_total": len(links),
        "internal_links": internal_links,
        "external_links": external_links,
        "scripts_with_src": len(scripts),
        "stylesheets_or_links": len(stylesheets),
        "forms": len(forms),
        "mixed_content": mixed_content[:50],
        "html_lang": soup.html.get("lang") if soup.html else None,
    }

def security_audit(url: str, response: requests.Response):
    parsed = urlparse(response.url)
    headers = {k.lower(): v for k, v in response.headers.items()}

    header_checks = {}
    for name, description in SECURITY_HEADERS.items():
        header_checks[name] = {
            "present": name in headers,
            "value": headers.get(name),
            "description": description,
        }

    set_cookie = response.headers.get("set-cookie", "")
    cookies = []
    if set_cookie:
        # Basic, non-invasive parsing for reporting cookie attributes.
        chunks = re.split(r",(?=\s*[^;,=]+=[^;,]+)", set_cookie)
        for cookie in chunks[:30]:
            first = cookie.split(";", 1)[0].strip()
            attrs = {part.strip().split("=", 1)[0].lower()
                     for part in cookie.split(";")[1:]}
            cookies.append({
                "name": first.split("=", 1)[0] if "=" in first else first,
                "secure": "secure" in attrs,
                "httponly": "httponly" in attrs,
                "samesite": any(a.startswith("samesite") for a in attrs),
            })

    tls = None
    if parsed.scheme == "https":
        tls = get_tls_info(parsed.hostname, parsed.port or 443)

    return {
        "https": parsed.scheme == "https",
        "headers": header_checks,
        "server_header": response.headers.get("server"),
        "powered_by": response.headers.get("x-powered-by"),
        "cookies": cookies,
        "tls": tls,
    }

def discover_files(base_url: str):
    results = {}
    for path in ("/robots.txt", "/sitemap.xml"):
        try:
            r = requests.get(
                urljoin(base_url, path),
                headers={"User-Agent": USER_AGENT},
                timeout=10,
                allow_redirects=True,
            )
            results[path] = {
                "status_code": r.status_code,
                "content_type": r.headers.get("content-type", ""),
                "exists": r.ok,
                "preview": r.text[:2000] if r.ok else "",
            }
        except Exception as exc:
            results[path] = {"exists": False, "error": str(exc)}
    return results

def pagespeed_audit(url: str, strategy: str):
    endpoint = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed"
    params = [
        ("url", url),
        ("strategy", strategy),
        ("category", "performance"),
        ("category", "accessibility"),
        ("category", "best-practices"),
        ("category", "seo"),
    ]
    r = requests.get(endpoint, params=params, timeout=90)
    r.raise_for_status()
    data = r.json()

    lighthouse = data.get("lighthouseResult", {})
    categories = lighthouse.get("categories", {})
    audits = lighthouse.get("audits", {})

    scores = {}
    for key in ("performance", "accessibility", "best-practices", "seo"):
        value = categories.get(key, {}).get("score")
        scores[key] = round(value * 100, 1) if value is not None else None

    selected = {}
    important_ids = [
        "first-contentful-paint",
        "largest-contentful-paint",
        "speed-index",
        "total-blocking-time",
        "cumulative-layout-shift",
        "interactive",
        "server-response-time",
        "render-blocking-resources",
        "unused-javascript",
        "unused-css-rules",
        "image-alt",
        "document-title",
        "meta-description",
        "robots-txt",
        "canonical",
        "is-crawlable",
        "viewport",
        "uses-https",
    ]
    for audit_id in important_ids:
        a = audits.get(audit_id)
        if not a:
            continue
        selected[audit_id] = {
            "title": a.get("title"),
            "score": a.get("score"),
            "display_value": a.get("displayValue"),
            "description": a.get("description"),
        }

    return {
        "strategy": strategy,
        "scores": scores,
        "metrics": selected,
        "fetch_time": data.get("analysisUTCTimestamp"),
    }

def gemini_report(url, collected):
    api_key = st.secrets.get("GEMINI_API_KEY", "")
    if not api_key:
        raise RuntimeError(
            "GEMINI_API_KEY is missing. Add it to Streamlit Secrets."
        )

    client = genai.Client(api_key=api_key)

    prompt = f"""
You are a senior website auditor. Analyze the passive audit data below for {url}.

Produce a professional website audit report in Markdown with:
1. Executive summary
2. Overall assessment (do not invent a numeric score unless supported by data)
3. SEO findings and prioritized fixes
4. Performance findings and prioritized fixes
5. Accessibility findings and prioritized fixes
6. Best-practices findings
7. Security findings, clearly separating:
   - observed security configuration issues
   - potential risks that require deeper testing
   - things that were NOT tested
8. Technical/UX findings
9. Priority table: Critical / High / Medium / Low
10. A practical 7-step remediation plan

Important:
- Never claim a vulnerability is confirmed when the data only indicates a missing header or a heuristic.
- This is a passive, non-intrusive audit. Do not recommend destructive or unauthorized testing.
- Explain why each important issue matters.
- Prefer concrete, developer-friendly fixes.
- If evidence is missing, say so.

DATA:
{json.dumps(collected, indent=2, default=str)[:90000]}
"""

    response = client.models.generate_content(
        model="gemini-3.7-flash",
        contents=prompt,
    )
    return response.text

def flatten_findings(collected):
    findings = []
    html = collected["html"]
    sec = collected["security"]
    ps = collected.get("pagespeed", {})

    if not html["title"]:
        findings.append(("High", "Missing page title"))
    elif not (10 <= html["title_length"] <= 60):
        findings.append(("Medium", f"Title length is {html['title_length']} characters"))

    if not html["meta_description"]:
        findings.append(("High", "Missing meta description"))
    elif not (50 <= html["meta_description_length"] <= 170):
        findings.append(("Medium", "Meta description length may need optimization"))

    if html["images_missing_alt"]:
        findings.append(("High", f"{len(html['images_missing_alt'])} images appear to lack alt text"))

    if html["mixed_content"]:
        findings.append(("High", f"{len(html['mixed_content'])} HTTP resources found on an HTTPS page"))

    if not sec["https"]:
        findings.append(("Critical", "The final page is not using HTTPS"))

    for name, check in sec["headers"].items():
        if not check["present"] and name in (
            "content-security-policy",
            "strict-transport-security",
            "x-content-type-options",
            "x-frame-options",
        ):
            findings.append(("Medium", f"Missing security header: {name}"))

    for cookie in sec["cookies"]:
        if not cookie["secure"] and sec["https"]:
            findings.append(("High", f"Cookie '{cookie['name']}' lacks Secure attribute"))
        if not cookie["httponly"]:
            findings.append(("Medium", f"Cookie '{cookie['name']}' lacks HttpOnly attribute"))

    for category, score in ps.get("scores", {}).items():
        if score is not None and score < 50:
            findings.append(("High", f"PageSpeed {category} score is {score}"))
        elif score is not None and score < 80:
            findings.append(("Medium", f"PageSpeed {category} score is {score}"))

    return findings

st.title("🔎 AI Website Auditor")
st.caption("Passive SEO • Performance • Accessibility • Best Practices • Security • Gemini AI analysis")

with st.sidebar:
    st.header("Audit settings")
    strategy = st.selectbox("PageSpeed device", ["mobile", "desktop"])
    run_gemini = st.checkbox("Generate Gemini AI report", value=True)
    st.info(
        "Security checks are passive. This tool does not exploit vulnerabilities, "
        "brute-force endpoints, or perform destructive penetration testing."
    )

url_input = st.text_input(
    "Website URL",
    placeholder="https://example.com",
)

if st.button("🚀 Run Website Audit", type="primary", use_container_width=True):
    try:
        url = normalize_url(url_input)
    except ValueError as exc:
        st.error(str(exc))
        st.stop()

    progress = st.progress(0)
    status = st.empty()

    try:
        status.write("Fetching website...")
        response = fetch_page(url)
        progress.progress(20)

        status.write("Analyzing HTML, SEO and technical structure...")
        html = analyze_html(url, response)
        progress.progress(40)

        status.write("Checking passive security configuration...")
        security = security_audit(url, response)
        progress.progress(55)

        status.write("Checking robots.txt and sitemap...")
        discovery = discover_files(response.url)
        progress.progress(65)

        status.write("Running Google PageSpeed Insights...")
        ps = pagespeed_audit(response.url, strategy)
        progress.progress(85)

        collected = {
            "url": url,
            "html": html,
            "security": security,
            "discovery": discovery,
            "pagespeed": ps,
        }

        findings = flatten_findings(collected)
        collected["prioritized_findings"] = findings

        progress.progress(90)

        if run_gemini:
            status.write("Gemini is generating the audit report...")
            ai_report = gemini_report(response.url, collected)
        else:
            ai_report = "Gemini report disabled."

        progress.progress(100)
        status.write("Audit completed.")

        st.session_state["audit"] = collected
        st.session_state["ai_report"] = ai_report

    except requests.RequestException as exc:
        st.error(f"Could not audit the website: {exc}")
        st.stop()
    except Exception as exc:
        st.error(f"Audit failed: {exc}")
        st.stop()

if "audit" in st.session_state:
    audit = st.session_state["audit"]
    html = audit["html"]
    ps = audit["pagespeed"]
    sec = audit["security"]

    st.divider()
    st.subheader("Overview")

    cols = st.columns(4)
    scores = ps.get("scores", {})
    labels = [
        ("Performance", scores.get("performance")),
        ("SEO", scores.get("seo")),
        ("Accessibility", scores.get("accessibility")),
        ("Best Practices", scores.get("best-practices")),
    ]
    for col, (label, value) in zip(cols, labels):
        with col:
            st.metric(label, f"{value}" if value is not None else "N/A")

    st.write(f"**Final URL:** {html['final_url']}")
    st.write(f"**HTTP status:** {html['status_code']}")
    st.write(f"**Initial response time:** {html['response_time_seconds']} s")
    st.write(f"**Page size:** {html['page_size_kb']} KB")

    st.subheader("Prioritized Findings")
    if audit["prioritized_findings"]:
        for severity, finding in audit["prioritized_findings"]:
            st.markdown(f"- **{severity}** — {finding}")
    else:
        st.success("No obvious issues were detected by the passive checks.")

    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(
        ["🤖 Gemini Report", "🔍 SEO", "⚡ Performance", "🛡️ Security", "♿ Accessibility", "🧰 Technical"]
    )

    with tab1:
        st.markdown(st.session_state["ai_report"])

    with tab2:
        st.write(f"**Title:** {html['title'] or 'Missing'}")
        st.write(f"**Title length:** {html['title_length']}")
        st.write(f"**Meta description:** {html['meta_description'] or 'Missing'}")
        st.write(f"**Meta description length:** {html['meta_description_length']}")
        st.write(f"**Canonical:** {html['canonical'] or 'Missing'}")
        st.write(f"**Language:** {html['html_lang'] or 'Missing'}")
        st.write(f"**H1 count:** {html['headings']['h1']}")
        st.write(f"**Images:** {html['images_total']}")
        st.write(f"**Images missing alt:** {len(html['images_missing_alt'])}")
        st.write(f"**Internal links:** {html['internal_links']}")
        st.write(f"**External links:** {html['external_links']}")
        st.write(f"**robots.txt:** {'Found' if audit['discovery']['/robots.txt'].get('exists') else 'Not found'}")
        st.write(f"**sitemap.xml:** {'Found' if audit['discovery']['/sitemap.xml'].get('exists') else 'Not found'}")

    with tab3:
        st.json(ps)

    with tab4:
        st.write(f"**HTTPS:** {'Yes' if sec['https'] else 'No'}")
        for name, info in sec["headers"].items():
            st.write(f"**{name}:** {'Present' if info['present'] else 'Missing'}")
        if sec.get("server_header"):
            st.write(f"**Server header:** {sec['server_header']}")
        if sec.get("powered_by"):
            st.write(f"**X-Powered-By:** {sec['powered_by']}")
        if sec.get("cookies"):
            st.write("**Cookie flags:**")
            st.json(sec["cookies"])
        if sec.get("tls"):
            st.write("**TLS:**")
            st.json(sec["tls"])

        st.warning(
            "A missing security header is not automatically a confirmed vulnerability. "
            "A real penetration test requires deeper, authorized testing."
        )

    with tab5:
        st.json({
            k: v for k, v in ps.get("metrics", {}).items()
            if k in ("image-alt", "document-title", "meta-description", "viewport")
        })

    with tab6:
        st.json({
            "headings": html["headings"],
            "scripts_with_src": html["scripts_with_src"],
            "stylesheets_or_links": html["stylesheets_or_links"],
            "forms": html["forms"],
            "mixed_content": html["mixed_content"],
            "content_type": html["content_type"],
        })

    report_json = json.dumps(audit, indent=2, default=str)
    st.download_button(
        "⬇️ Download raw audit JSON",
        data=report_json,
        file_name=f"website-audit-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json",
        mime="application/json",
    )
