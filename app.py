import json
import re
import socket
import ssl
import time
from urllib.parse import urljoin, urlparse

import requests
import streamlit as st
from bs4 import BeautifulSoup
from google import genai
from playwright.sync_api import sync_playwright


# ============================================================
# CONFIG
# ============================================================

st.set_page_config(
    page_title="AI Website Auditor",
    page_icon="🔎",
    layout="wide",
)

USER_AGENT = "AI-Website-Auditor/1.0"
REQUEST_TIMEOUT = 20


# ============================================================
# URL HELPERS
# ============================================================

def normalize_url(url: str) -> str:
    url = url.strip()

    if not url:
        raise ValueError("Please enter a website URL.")

    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url

    parsed = urlparse(url)

    if not parsed.netloc:
        raise ValueError("Invalid website URL.")

    return url


# ============================================================
# BASIC HTTP FETCH
# ============================================================

def fetch_website(url):
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml",
    }

    start = time.perf_counter()

    response = requests.get(
        url,
        headers=headers,
        timeout=REQUEST_TIMEOUT,
        allow_redirects=True,
    )

    elapsed = time.perf_counter() - start

    return response, elapsed


# ============================================================
# SEO / HTML ANALYSIS
# ============================================================

def analyze_html(url, response):

    soup = BeautifulSoup(response.text, "html.parser")

    parsed = urlparse(response.url)

    # -------------------------
    # Title
    # -------------------------

    title_tag = soup.find("title")

    title = (
        title_tag.get_text(" ", strip=True)
        if title_tag
        else ""
    )

    # -------------------------
    # Meta description
    # -------------------------

    meta_description_tag = soup.find(
        "meta",
        attrs={"name": re.compile("^description$", re.I)}
    )

    meta_description = (
        meta_description_tag.get("content", "").strip()
        if meta_description_tag
        else ""
    )

    # -------------------------
    # Canonical
    # -------------------------

    canonical_tag = soup.find(
        "link",
        rel=lambda value:
        value and "canonical" in value
    )

    canonical = (
        canonical_tag.get("href", "").strip()
        if canonical_tag
        else ""
    )

    # -------------------------
    # Robots
    # -------------------------

    robots_tag = soup.find(
        "meta",
        attrs={"name": re.compile("^robots$", re.I)}
    )

    robots = (
        robots_tag.get("content", "").strip()
        if robots_tag
        else ""
    )

    # -------------------------
    # Viewport
    # -------------------------

    viewport_tag = soup.find(
        "meta",
        attrs={"name": re.compile("^viewport$", re.I)}
    )

    viewport = (
        viewport_tag.get("content", "").strip()
        if viewport_tag
        else ""
    )

    # -------------------------
    # Language
    # -------------------------

    html_tag = soup.find("html")

    language = (
        html_tag.get("lang")
        if html_tag
        else None
    )

    # -------------------------
    # Headings
    # -------------------------

    headings = {}

    for level in range(1, 7):
        headings[f"h{level}"] = len(
            soup.find_all(f"h{level}")
        )

    # -------------------------
    # Images
    # -------------------------

    images = soup.find_all("img")

    images_without_alt = []

    for img in images:

        alt = img.get("alt")

        if not alt or not alt.strip():

            images_without_alt.append(
                img.get("src", "")[:250]
            )

    # -------------------------
    # Links
    # -------------------------

    links = soup.find_all("a", href=True)

    internal_links = 0
    external_links = 0

    for link in links:

        href = urljoin(
            response.url,
            link["href"]
        )

        parsed_link = urlparse(href)

        if not parsed_link.netloc:
            continue

        if parsed_link.netloc == parsed.netloc:
            internal_links += 1

        else:
            external_links += 1

    # -------------------------
    # Scripts
    # -------------------------

    scripts = soup.find_all(
        "script",
        src=True
    )

    # -------------------------
    # Stylesheets
    # -------------------------

    stylesheets = soup.find_all(
        "link",
        rel=lambda value:
        value and "stylesheet" in value
    )

    # -------------------------
    # Forms
    # -------------------------

    forms = soup.find_all("form")

    # -------------------------
    # Schema / JSON-LD
    # -------------------------

    json_ld = soup.find_all(
        "script",
        attrs={
            "type": "application/ld+json"
        }
    )

    # -------------------------
    # Mixed content
    # -------------------------

    mixed_content = []

    if parsed.scheme == "https":

        for tag in soup.find_all(src=True):

            src = urljoin(
                response.url,
                tag.get("src")
            )

            if src.startswith("http://"):
                mixed_content.append(src[:250])

        for tag in soup.find_all(href=True):

            href = urljoin(
                response.url,
                tag.get("href")
            )

            if href.startswith("http://"):
                mixed_content.append(href[:250])

    return {

        "url": response.url,

        "status_code":
            response.status_code,

        "content_type":
            response.headers.get(
                "content-type",
                ""
            ),

        "server":
            response.headers.get(
                "server"
            ),

        "response_time_seconds":
            round(
                response.elapsed.total_seconds(),
                3
            ),

        "page_size_kb":
            round(
                len(response.content) / 1024,
                2
            ),

        "title":
            title,

        "title_length":
            len(title),

        "meta_description":
            meta_description,

        "meta_description_length":
            len(meta_description),

        "canonical":
            canonical,

        "robots_meta":
            robots,

        "viewport":
            viewport,

        "language":
            language,

        "headings":
            headings,

        "images_total":
            len(images),

        "images_without_alt":
            images_without_alt[:100],

        "links_total":
            len(links),

        "internal_links":
            internal_links,

        "external_links":
            external_links,

        "scripts":
            len(scripts),

        "stylesheets":
            len(stylesheets),

        "forms":
            len(forms),

        "structured_data_count":
            len(json_ld),

        "mixed_content":
            mixed_content[:100],
    }


# ============================================================
# SECURITY ANALYSIS
# ============================================================

def get_tls_information(hostname):

    try:

        context = ssl.create_default_context()

        with socket.create_connection(
            (hostname, 443),
            timeout=8
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=hostname
            ) as tls:

                certificate = tls.getpeercert()

                return {

                    "tls_version":
                        tls.version(),

                    "cipher":
                        tls.cipher()[0]
                        if tls.cipher()
                        else None,

                    "certificate_subject":
                        str(
                            certificate.get(
                                "subject"
                            )
                        ),

                    "certificate_issuer":
                        str(
                            certificate.get(
                                "issuer"
                            )
                        ),
                }

    except Exception as e:

        return {
            "error": str(e)
        }


def analyze_security(url, response):

    parsed = urlparse(response.url)

    headers = {
        key.lower(): value
        for key, value
        in response.headers.items()
    }

    security_headers = {

        "content-security-policy":
            "Protects against many forms of XSS and unwanted resource execution.",

        "strict-transport-security":
            "Forces browsers to use HTTPS.",

        "x-content-type-options":
            "Helps prevent MIME type sniffing.",

        "x-frame-options":
            "Helps protect against clickjacking.",

        "referrer-policy":
            "Controls referrer information.",

        "permissions-policy":
            "Controls browser features and permissions.",
    }

    header_results = {}

    for name, description in security_headers.items():

        header_results[name] = {

            "present":
                name in headers,

            "value":
                headers.get(name),

            "description":
                description,
        }

    # -------------------------
    # Cookies
    # -------------------------

    cookies = []

    set_cookie = response.headers.get(
        "set-cookie",
        ""
    )

    if set_cookie:

        cookie_parts = re.split(
            r",(?=\s*[^;,=]+=[^;,]+)",
            set_cookie
        )

        for cookie in cookie_parts[:50]:

            parts = cookie.split(";")

            first = parts[0].strip()

            if "=" not in first:
                continue

            cookie_name = first.split(
                "=",
                1
            )[0]

            attributes = [
                part.strip().lower()
                for part in parts[1:]
            ]

            cookies.append({

                "name":
                    cookie_name,

                "secure":
                    "secure" in attributes,

                "httponly":
                    "httponly" in attributes,

                "samesite":
                    any(
                        item.startswith(
                            "samesite"
                        )
                        for item in attributes
                    ),
            })

    tls = None

    if parsed.scheme == "https":

        tls = get_tls_information(
            parsed.hostname
        )

    return {

        "https":
            parsed.scheme == "https",

        "security_headers":
            header_results,

        "cookies":
            cookies,

        "server":
            response.headers.get(
                "server"
            ),

        "x_powered_by":
            response.headers.get(
                "x-powered-by"
            ),

        "tls":
            tls,
    }


# ============================================================
# ROBOTS / SITEMAP
# ============================================================

def check_robots_and_sitemap(url):

    results = {}

    for path in [
        "/robots.txt",
        "/sitemap.xml"
    ]:

        target = urljoin(
            url,
            path
        )

        try:

            response = requests.get(
                target,
                headers={
                    "User-Agent":
                        USER_AGENT
                },
                timeout=10
            )

            results[path] = {

                "exists":
                    response.ok,

                "status":
                    response.status_code,

                "preview":
                    response.text[:2000]
                    if response.ok
                    else "",
            }

        except Exception as e:

            results[path] = {

                "exists":
                    False,

                "error":
                    str(e),
            }

    return results


# ============================================================
# PLAYWRIGHT PERFORMANCE AUDIT
# ============================================================

def browser_audit(url):

    result = {

        "navigation_time_ms": None,

        "dom_content_loaded_ms": None,

        "load_event_ms": None,

        "first_contentful_paint_ms": None,

        "largest_contentful_paint_ms": None,

        "cumulative_layout_shift": None,

        "request_count": 0,

        "failed_requests": [],

        "resource_summary": {},

        "console_errors": [],

        "page_title": "",
    }

    with sync_playwright() as p:

        browser = p.chromium.launch(
            headless=True
        )

        page = browser.new_page(
            viewport={
                "width": 1280,
                "height": 720
            }
        )

        resources = []

        failed_requests = []

        console_errors = []

        page.on(
            "response",
            lambda response:
            resources.append({
                "url":
                    response.url,
                "status":
                    response.status,
                "resource_type":
                    response.request.resource_type,
            })
        )

        page.on(
            "requestfailed",
            lambda request:
            failed_requests.append({
                "url":
                    request.url,
                "failure":
                    request.failure,
            })
        )

        page.on(
            "console",
            lambda msg:
            console_errors.append(
                msg.text
            )
            if msg.type == "error"
            else None
        )

        start = time.perf_counter()

        page.goto(
            url,
            wait_until="networkidle",
            timeout=60000
        )

        navigation_time = (
            time.perf_counter() - start
        ) * 1000

        # Give browser performance APIs
        # time to populate.

        time.sleep(1)

        metrics = page.evaluate(
            """
            () => {

                const navigation =
                    performance.getEntriesByType(
                        'navigation'
                    )[0];

                const paints =
                    performance.getEntriesByType(
                        'paint'
                    );

                let fcp = null;

                for (const paint of paints) {

                    if (
                        paint.name ===
                        'first-contentful-paint'
                    ) {
                        fcp = paint.startTime;
                    }
                }

                return {

                    domContentLoaded:
                        navigation
                        ? navigation.domContentLoadedEventEnd
                        : null,

                    loadEvent:
                        navigation
                        ? navigation.loadEventEnd
                        : null,

                    fcp: fcp,

                    resourceCount:
                        performance
                        .getEntriesByType(
                            'resource'
                        ).length
                };
            }
            """
        )

        # LCP
        lcp = page.evaluate(
            """
            () => new Promise(resolve => {

                let value = null;

                try {

                    const observer =
                        new PerformanceObserver(
                            list => {

                                const entries =
                                    list.getEntries();

                                if (entries.length) {

                                    value =
                                        entries[
                                            entries.length - 1
                                        ].startTime;
                                }
                            }
                        );

                    observer.observe({
                        type: 'largest-contentful-paint',
                        buffered: true
                    });

                } catch (e) {}

                setTimeout(
                    () => resolve(value),
                    500
                );
            })
            """
        )

        # CLS
        cls = page.evaluate(
            """
            () => {

                let value = 0;

                try {

                    const entries =
                        performance.getEntriesByType(
                            'layout-shift'
                        );

                    for (
                        const entry of entries
                    ) {

                        if (
                            !entry.hadRecentInput
                        ) {

                            value +=
                                entry.value;
                        }
                    }

                } catch (e) {}

                return value;
            }
            """
        )

        result["navigation_time_ms"] = round(
            navigation_time,
            2
        )

        result["dom_content_loaded_ms"] = (
            round(
                metrics["domContentLoaded"],
                2
            )
            if metrics["domContentLoaded"]
            else None
        )

        result["load_event_ms"] = (
            round(
                metrics["loadEvent"],
                2
            )
            if metrics["loadEvent"]
            else None
        )

        result["first_contentful_paint_ms"] = (
            round(
                metrics["fcp"],
                2
            )
            if metrics["fcp"]
            else None
        )

        result["largest_contentful_paint_ms"] = (
            round(
                lcp,
                2
            )
            if lcp
            else None
        )

        result["cumulative_layout_shift"] = (
            round(cls, 4)
            if cls is not None
            else None
        )

        result["request_count"] = (
            len(resources)
        )

        result["failed_requests"] = (
            failed_requests[:100]
        )

        result["console_errors"] = (
            console_errors[:50]
        )

        result["resource_summary"] = {

            "documents":
                len([
                    r for r in resources
                    if r["resource_type"]
                    == "document"
                ]),

            "scripts":
                len([
                    r for r in resources
                    if r["resource_type"]
                    == "script"
                ]),

            "stylesheets":
                len([
                    r for r in resources
                    if r["resource_type"]
                    == "stylesheet"
                ]),

            "images":
                len([
                    r for r in resources
                    if r["resource_type"]
                    == "image"
                ]),

            "fonts":
                len([
                    r for r in resources
                    if r["resource_type"]
                    == "font"
                ]),

            "xhr_fetch":
                len([
                    r for r in resources
                    if r["resource_type"]
                    in ["xhr", "fetch"]
                ]),
        }

        result["page_title"] = page.title()

        browser.close()

    return result


# ============================================================
# LOCAL FINDINGS
# ============================================================

def generate_findings(audit):

    findings = []

    html = audit["html"]
    security = audit["security"]
    performance = audit["performance"]

    # SEO
    if not html["title"]:

        findings.append({
            "severity": "High",
            "category": "SEO",
            "issue": "Missing page title",
        })

    elif not 10 <= html["title_length"] <= 60:

        findings.append({
            "severity": "Medium",
            "category": "SEO",
            "issue":
                f"Title length is {html['title_length']} characters.",
        })

    if not html["meta_description"]:

        findings.append({
            "severity": "High",
            "category": "SEO",
            "issue":
                "Missing meta description.",
        })

    if html["images_without_alt"]:

        findings.append({
            "severity": "High",
            "category": "Accessibility",
            "issue":
                f"{len(html['images_without_alt'])} images are missing alt text.",
        })

    if html["headings"]["h1"] == 0:

        findings.append({
            "severity": "Medium",
            "category": "SEO",
            "issue":
                "No H1 heading detected.",
        })

    if html["headings"]["h1"] > 1:

        findings.append({
            "severity": "Low",
            "category": "SEO",
            "issue":
                "Multiple H1 headings detected.",
        })

    if not html["canonical"]:

        findings.append({
            "severity": "Medium",
            "category": "SEO",
            "issue":
                "Canonical URL was not detected.",
        })

    if not html["viewport"]:

        findings.append({
            "severity": "High",
            "category": "Mobile",
            "issue":
                "Viewport meta tag is missing.",
        })

    # Security
    if not security["https"]:

        findings.append({
            "severity": "Critical",
            "category": "Security",
            "issue":
                "Website is not using HTTPS.",
        })

    important_headers = [
        "content-security-policy",
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
    ]

    for header in important_headers:

        if not security[
            "security_headers"
        ][header]["present"]:

            findings.append({
                "severity": "Medium",
                "category": "Security",
                "issue":
                    f"Missing security header: {header}",
            })

    # Performance
    fcp = performance[
        "first_contentful_paint_ms"
    ]

    if fcp and fcp > 3000:

        findings.append({
            "severity": "High",
            "category": "Performance",
            "issue":
                f"First Contentful Paint is approximately {fcp:.0f} ms.",
        })

    lcp = performance[
        "largest_contentful_paint_ms"
    ]

    if lcp and lcp > 4000:

        findings.append({
            "severity": "High",
            "category": "Performance",
            "issue":
                f"Large Contentful Paint is approximately {lcp:.0f} ms.",
        })

    if performance["request_count"] > 150:

        findings.append({
            "severity": "Medium",
            "category": "Performance",
            "issue":
                f"High number of network requests: {performance['request_count']}.",
        })

    if performance["failed_requests"]:

        findings.append({
            "severity": "Medium",
            "category": "Technical",
            "issue":
                f"{len(performance['failed_requests'])} network requests failed.",
        })

    return findings


# ============================================================
# GEMINI
# ============================================================

def generate_gemini_report(url, audit):

    api_key = st.secrets.get(
        "GEMINI_API_KEY"
    )

    if not api_key:

        raise RuntimeError(
            "GEMINI_API_KEY is missing from Streamlit Secrets."
        )

    client = genai.Client(
        api_key=api_key
    )

    prompt = f"""
You are a senior website auditor and technical SEO expert.

Analyze the following passive website audit.

Website:
{url}

AUDIT DATA:
{json.dumps(
    audit,
    indent=2,
    default=str
)[:100000]}

Create a professional Markdown report containing:

# Website Audit Report

## 1. Executive Summary

Give a concise overview.

## 2. Overall Assessment

Discuss the general quality of the website.

## 3. SEO Audit

Analyze:
- Title
- Meta description
- Headings
- Canonical
- Robots
- Sitemap
- Images
- Internal links
- Structured data
- Crawlability signals

## 4. Performance Audit

Analyze:
- Navigation/load time
- FCP
- LCP
- CLS
- Number of requests
- JavaScript
- CSS
- Images
- Failed requests

Explain what should be improved.

## 5. Security Audit

Analyze:
- HTTPS
- Security headers
- Cookies
- TLS
- Mixed content

IMPORTANT:
Do NOT claim that a vulnerability is confirmed merely because
a security header is missing.

Clearly distinguish:
- Confirmed observations
- Potential risks
- Things that were not tested

This is a passive audit and NOT a penetration test.

## 6. Accessibility Audit

Discuss the available accessibility signals.

## 7. Technical Audit

Discuss:
- HTTP status
- HTML structure
- resources
- JavaScript
- forms
- links
- structured data

## 8. Mobile / Responsive Audit

Discuss mobile-related findings based on the collected data.

## 9. Priority Issues

Create a table:

| Priority | Category | Issue | Why it matters | Recommended fix |
|---|---|---|---|---|

Use Critical, High, Medium, Low.

## 10. Recommended Action Plan

Give the top 10 practical improvements in order.

Be technically accurate.

Never invent data that does not exist in the audit.
"""

    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=prompt,
    )

    return response.text


# ============================================================
# STREAMLIT UI
# ============================================================

st.title("🔎 AI Website Auditor")

st.markdown(
    """
Enter any **public website URL** and generate a detailed audit
covering **SEO, Performance, Security, Accessibility and Technical
issues** using real browser measurements and Gemini AI.
"""
)

with st.sidebar:

    st.header("Audit Settings")

    mobile = st.checkbox(
        "Mobile viewport",
        value=False
    )

    use_gemini = st.checkbox(
        "Generate Gemini AI report",
        value=True
    )

    st.divider()

    st.info(
        """
Security testing is passive.

This application does not:
- exploit vulnerabilities
- brute force
- bypass authentication
- attack endpoints
- perform destructive penetration testing
"""
    )


url_input = st.text_input(
    "Website URL",
    placeholder="https://example.com"
)


if st.button(
    "🚀 Run Complete Audit",
    type="primary",
    use_container_width=True
):

    try:

        url = normalize_url(
            url_input
        )

    except ValueError as e:

        st.error(str(e))
        st.stop()

    progress = st.progress(0)

    status = st.empty()

    try:

        # -----------------------------
        # HTTP
        # -----------------------------

        status.write(
            "🌐 Fetching website..."
        )

        response, fetch_time = (
            fetch_website(url)
        )

        progress.progress(15)

        # -----------------------------
        # HTML
        # -----------------------------

        status.write(
            "🔍 Analyzing SEO and HTML..."
        )

        html = analyze_html(
            url,
            response
        )

        progress.progress(30)

        # -----------------------------
        # Security
        # -----------------------------

        status.write(
            "🛡️ Analyzing security..."
        )

        security = analyze_security(
            url,
            response
        )

        progress.progress(45)

        # -----------------------------
        # Robots/Sitemap
        # -----------------------------

        status.write(
            "🤖 Checking robots.txt and sitemap..."
        )

        discovery = (
            check_robots_and_sitemap(
                response.url
            )
        )

        progress.progress(55)

        # -----------------------------
        # Browser performance
        # -----------------------------

        status.write(
            "⚡ Running browser performance audit..."
        )

        performance = browser_audit(
            response.url
        )

        progress.progress(75)

        # -----------------------------
        # Complete data
        # -----------------------------

        audit = {

            "website":
                response.url,

            "fetch_time":
                fetch_time,

            "html":
                html,

            "security":
                security,

            "discovery":
                discovery,

            "performance":
                performance,
        }

        # -----------------------------
        # Findings
        # -----------------------------

        findings = generate_findings(
            audit
        )

        audit["findings"] = findings

        progress.progress(85)

        # -----------------------------
        # Gemini
        # -----------------------------

        if use_gemini:

            status.write(
                "🤖 Gemini is analyzing the website..."
            )

            gemini_report = (
                generate_gemini_report(
                    response.url,
                    audit
                )
            )

        else:

            gemini_report = (
                "Gemini report disabled."
            )

        progress.progress(100)

        status.write(
            "✅ Audit completed."
        )

        st.session_state[
            "audit"
        ] = audit

        st.session_state[
            "gemini_report"
        ] = gemini_report

    except Exception as e:

        st.error(
            f"Audit failed: {str(e)}"
        )

        st.stop()


# ============================================================
# RESULTS
# ============================================================

if "audit" in st.session_state:

    audit = st.session_state[
        "audit"
    ]

    html = audit["html"]

    performance = audit[
        "performance"
    ]

    security = audit[
        "security"
    ]

    findings = audit[
        "findings"
    ]

    st.divider()

    st.header("📊 Audit Overview")

    columns = st.columns(5)

    metrics = [

        (
            "HTTP Status",
            html["status_code"]
        ),

        (
            "Load Time",
            f"{performance['navigation_time_ms']} ms"
        ),

        (
            "FCP",
            f"{performance['first_contentful_paint_ms']} ms"
            if performance[
                "first_contentful_paint_ms"
            ]
            else "N/A"
        ),

        (
            "LCP",
            f"{performance['largest_contentful_paint_ms']} ms"
            if performance[
                "largest_contentful_paint_ms"
            ]
            else "N/A"
        ),

        (
            "Requests",
            performance[
                "request_count"
            ]
        ),
    ]

    for column, (label, value) in zip(
        columns,
        metrics
    ):

        column.metric(
            label,
            value
        )

    # ========================================================
    # FINDINGS
    # ========================================================

    st.header("🚨 Detected Issues")

    if not findings:

        st.success(
            "No obvious issues were detected."
        )

    else:

        severity_order = {
            "Critical": 0,
            "High": 1,
            "Medium": 2,
            "Low": 3,
        }

        findings = sorted(
            findings,
            key=lambda item:
                severity_order.get(
                    item["severity"],
                    99
                )
        )

        for finding in findings:

            st.markdown(
                f"""
**{finding['severity']}** ·
{finding['category']}

{finding['issue']}
"""
            )

    # ========================================================
    # TABS
    # ========================================================

    tabs = st.tabs(
        [
            "🤖 Gemini Report",
            "🔍 SEO",
            "⚡ Performance",
            "🛡️ Security",
            "♿ Accessibility",
            "🧰 Technical",
            "📦 Raw Data",
        ]
    )

    # ========================================================
    # GEMINI
    # ========================================================

    with tabs[0]:

        st.markdown(
            st.session_state[
                "gemini_report"
            ]
        )

    # ========================================================
    # SEO
    # ========================================================

    with tabs[1]:

        st.subheader(
            "SEO Analysis"
        )

        st.write(
            "**Title:**",
            html["title"]
            or "Missing"
        )

        st.write(
            "**Title length:**",
            html["title_length"]
        )

        st.write(
            "**Meta description:**",
            html["meta_description"]
            or "Missing"
        )

        st.write(
            "**Meta description length:**",
            html[
                "meta_description_length"
            ]
        )

        st.write(
            "**Canonical:**",
            html["canonical"]
            or "Missing"
        )

        st.write(
            "**Robots meta:**",
            html["robots_meta"]
            or "Not specified"
        )

        st.write(
            "**Language:**",
            html["language"]
            or "Missing"
        )

        st.write(
            "**H1:**",
            html["headings"]["h1"]
        )

        st.write(
            "**Images:**",
            html["images_total"]
        )

        st.write(
            "**Images without alt:**",
            len(
                html[
                    "images_without_alt"
                ]
            )
        )

        st.write(
            "**Internal links:**",
            html["internal_links"]
        )

        st.write(
            "**External links:**",
            html["external_links"]
        )

        st.write(
            "**Structured data blocks:**",
            html[
                "structured_data_count"
            ]
        )

        st.write(
            "**robots.txt:**",
            "Found"
            if audit[
                "discovery"
            ]["/robots.txt"].get(
                "exists"
            )
            else "Not found"
        )

        st.write(
            "**sitemap.xml:**",
            "Found"
            if audit[
                "discovery"
            ]["/sitemap.xml"].get(
                "exists"
            )
            else "Not found"
        )

    # ========================================================
    # PERFORMANCE
    # ========================================================

    with tabs[2]:

        st.subheader(
            "Browser Performance"
        )

        performance_display = {

            "Navigation time":
                performance[
                    "navigation_time_ms"
                ],

            "DOM Content Loaded":
                performance[
                    "dom_content_loaded_ms"
                ],

            "Load event":
                performance[
                    "load_event_ms"
                ],

            "First Contentful Paint":
                performance[
                    "first_contentful_paint_ms"
                ],

            "Largest Contentful Paint":
                performance[
                    "largest_contentful_paint_ms"
                ],

            "Cumulative Layout Shift":
                performance[
                    "cumulative_layout_shift"
                ],

            "Network requests":
                performance[
                    "request_count"
                ],

            "Failed requests":
                len(
                    performance[
                        "failed_requests"
                    ]
                ),
        }

        st.json(
            performance_display
        )

        st.subheader(
            "Resource Breakdown"
        )

        st.json(
            performance[
                "resource_summary"
            ]
        )

    # ========================================================
    # SECURITY
    # ========================================================

    with tabs[3]:

        st.subheader(
            "Security Configuration"
        )

        st.write(
            "**HTTPS:**",
            "Enabled"
            if security["https"]
            else "Not enabled"
        )

        st.subheader(
            "Security Headers"
        )

        for (
            header,
            data
        ) in security[
            "security_headers"
        ].items():

            if data["present"]:

                st.success(
                    f"✓ {header}"
                )

            else:

                st.warning(
                    f"⚠ Missing: {header}"
                )

        st.subheader(
            "TLS"
        )

        st.json(
            security["tls"]
            or {}
        )

        if security["cookies"]:

            st.subheader(
                "Cookie Security"
            )

            st.json(
                security["cookies"]
            )

        st.warning(
            "These are passive security observations. "
            "Missing headers do not by themselves prove "
            "that the website is vulnerable."
        )

    # ========================================================
    # ACCESSIBILITY
    # ========================================================

    with tabs[4]:

        st.subheader(
            "Accessibility Signals"
        )

        st.write(
            "**Images without alt:**",
            len(
                html[
                    "images_without_alt"
                ]
            )
        )

        st.write(
            "**Viewport:**",
            html["viewport"]
            or "Missing"
        )

        st.write(
            "**HTML language:**",
            html["language"]
            or "Missing"
        )

        st.write(
            "**H1 headings:**",
            html["headings"]["h1"]
        )

        st.write(
            "**Forms:**",
            html["forms"]
        )

    # ========================================================
    # TECHNICAL
    # ========================================================

    with tabs[5]:

        st.subheader(
            "Technical Information"
        )

        st.json({

            "url":
                html["url"],

            "status":
                html["status_code"],

            "content_type":
                html["content_type"],

            "page_size_kb":
                html["page_size_kb"],

            "scripts":
                html["scripts"],

            "stylesheets":
                html["stylesheets"],

            "forms":
                html["forms"],

            "mixed_content":
                html["mixed_content"],

            "failed_requests":
                performance[
                    "failed_requests"
                ],

            "console_errors":
                performance[
                    "console_errors"
                ],
        })

    # ========================================================
    # RAW
    # ========================================================

    with tabs[6]:

        st.json(
            audit
        )

        st.download_button(
            "⬇️ Download Audit JSON",
            data=json.dumps(
                audit,
                indent=2,
                default=str
            ),
            file_name=(
                "website_audit.json"
            ),
            mime="application/json",
        )