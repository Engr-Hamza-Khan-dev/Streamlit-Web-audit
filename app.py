import json, re, socket, ssl, time
from urllib.parse import urljoin, urlparse
import requests
import streamlit as st
from bs4 import BeautifulSoup
from google import genai

st.set_page_config(page_title="AI Website Auditor", page_icon="🔎", layout="wide")
UA = "AI-Website-Auditor/2.0"
TIMEOUT = 20

def normalize_url(url):
    url = url.strip()
    if not url: raise ValueError("Please enter a website URL.")
    if not re.match(r"^https?://", url, re.I): url = "https://" + url
    p = urlparse(url)
    if p.scheme not in ("http","https") or not p.netloc: raise ValueError("Enter a valid HTTP/HTTPS URL.")
    return url

def fetch(url):
    s = requests.Session()
    s.headers.update({"User-Agent": UA, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"})
    start = time.perf_counter()
    r = s.get(url, timeout=TIMEOUT, allow_redirects=True)
    return r, time.perf_counter()-start

def analyze_html(r):
    soup = BeautifulSoup(r.text, "html.parser")
    p = urlparse(r.url)
    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    md = soup.find("meta", attrs={"name": re.compile("^description$", re.I)})
    desc = md.get("content","").strip() if md else ""
    can = soup.find("link", rel=lambda x: x and "canonical" in x)
    robots = soup.find("meta", attrs={"name": re.compile("^robots$", re.I)})
    viewport = soup.find("meta", attrs={"name": re.compile("^viewport$", re.I)})
    html = soup.find("html")
    images = soup.find_all("img")
    no_alt = [urljoin(r.url, x.get("src",""))[:300] for x in images if not x.get("alt","").strip()]
    links = soup.find_all("a", href=True)
    internal = external = 0
    for a in links:
        q = urlparse(urljoin(r.url,a["href"]))
        if q.netloc:
            if q.netloc == p.netloc: internal += 1
            else: external += 1
    scripts = [urljoin(r.url,x["src"]) for x in soup.find_all("script",src=True)]
    css = [urljoin(r.url,x["href"]) for x in soup.find_all("link",href=True,rel=lambda x:x and "stylesheet" in x)]
    imgs = [urljoin(r.url,x.get("src")) for x in images if x.get("src")]
    mixed = []
    if p.scheme == "https":
        for x in soup.find_all(src=True):
            q=urljoin(r.url,x.get("src"))
            if q.startswith("http://"): mixed.append(q[:300])
        for x in soup.find_all(href=True):
            q=urljoin(r.url,x.get("href"))
            if q.startswith("http://"): mixed.append(q[:300])
    unlabeled = 0
    for x in soup.find_all(["input","textarea","select"]):
        iid=x.get("id")
        if not ((iid and soup.find("label",attrs={"for":iid})) or x.get("aria-label") or x.get("aria-labelledby")):
            unlabeled += 1
    return {
        "final_url":r.url,"status_code":r.status_code,"content_type":r.headers.get("content-type",""),
        "server":r.headers.get("server"),"content_encoding":r.headers.get("content-encoding"),
        "cache_control":r.headers.get("cache-control"),"etag":r.headers.get("etag"),
        "page_size_kb":round(len(r.content)/1024,2),"title":title,"title_length":len(title),
        "meta_description":desc,"meta_description_length":len(desc),
        "canonical":can.get("href","").strip() if can else "",
        "robots_meta":robots.get("content","").strip() if robots else "",
        "viewport":viewport.get("content","").strip() if viewport else "",
        "language":html.get("lang") if html else None,
        "headings":{f"h{i}":len(soup.find_all(f"h{i}")) for i in range(1,7)},
        "images_total":len(images),"images_without_alt":no_alt[:100],
        "links_total":len(links),"internal_links":internal,"external_links":external,
        "scripts":len(scripts),"script_urls":scripts[:40],"stylesheets":len(css),"stylesheet_urls":css[:40],
        "forms":len(soup.find_all("form")),"unlabeled_form_controls":unlabeled,
        "structured_data_count":len(soup.find_all("script",attrs={"type":"application/ld+json"})),
        "mixed_content":mixed[:100],"image_urls":imgs[:40]
    }

def tls_info(host):
    try:
        ctx=ssl.create_default_context()
        with socket.create_connection((host,443),timeout=8) as sock:
            with ctx.wrap_socket(sock,server_hostname=host) as tls:
                cert=tls.getpeercert()
                return {"tls_version":tls.version(),"cipher":tls.cipher()[0] if tls.cipher() else None,
                        "certificate_subject":str(cert.get("subject")),"certificate_issuer":str(cert.get("issuer"))}
    except Exception as e: return {"error":str(e)}

def security(r):
    p=urlparse(r.url); h={k.lower():v for k,v in r.headers.items()}
    desc={
        "content-security-policy":"Controls browser resource execution.",
        "strict-transport-security":"Helps force HTTPS.",
        "x-content-type-options":"Reduces MIME sniffing.",
        "x-frame-options":"Helps reduce clickjacking.",
        "referrer-policy":"Controls referrer information.",
        "permissions-policy":"Controls browser capabilities."
    }
    headers={k:{"present":k in h,"value":h.get(k),"description":v} for k,v in desc.items()}
    return {"https":p.scheme=="https","headers":headers,"server":r.headers.get("server"),
            "x_powered_by":r.headers.get("x-powered-by"),
            "tls":tls_info(p.hostname) if p.scheme=="https" else None}

def discover(url,s):
    out={}
    for path in ("/robots.txt","/sitemap.xml"):
        try:
            r=s.get(urljoin(url,path),timeout=10,allow_redirects=True)
            out[path]={"exists":r.ok,"status":r.status_code,"content_type":r.headers.get("content-type"),"preview":r.text[:2500] if r.ok else ""}
        except Exception as e: out[path]={"exists":False,"error":str(e)}
    return out

def resource_check(url,s):
    try:
        start=time.perf_counter(); r=s.head(url,timeout=8,allow_redirects=True)
        if r.status_code >= 400 or r.status_code == 405:
            start=time.perf_counter(); r=s.get(url,timeout=8,allow_redirects=True,stream=True)
        return {"url":url,"status":r.status_code,"response_time_ms":round((time.perf_counter()-start)*1000,2),
                "content_type":r.headers.get("content-type"),"content_length":r.headers.get("content-length"),
                "cache_control":r.headers.get("cache-control"),"content_encoding":r.headers.get("content-encoding")}
    except Exception as e: return {"url":url,"status":None,"error":str(e)}

def resource_audit(html):
    s=requests.Session(); s.headers.update({"User-Agent":UA})
    urls=list(dict.fromkeys(html["script_urls"][:20]+html["stylesheet_urls"][:20]+html["image_urls"][:20]))
    items=[resource_check(u,s) for u in urls]
    ok=[x for x in items if x.get("status") and x["status"]<400]
    failed=[x for x in items if not x.get("status") or x["status"]>=400]
    times=[x["response_time_ms"] for x in ok if x.get("response_time_ms") is not None]
    return {"checked":len(items),"successful":len(ok),"failed":len(failed),"failed_resources":failed[:50],
            "average_response_time_ms":round(sum(times)/len(times),2) if times else None,
            "slow_resources":[x for x in ok if x.get("response_time_ms",0)>1000][:50]}

def findings(a):
    h=a["html"]; sec=a["security"]; res=a["resources"]; f=[]
    def add(sev,cat,msg): f.append({"severity":sev,"category":cat,"issue":msg})
    if not h["title"]: add("High","SEO","Missing page title.")
    elif not 10<=h["title_length"]<=60: add("Medium","SEO",f"Title length is {h['title_length']} characters.")
    if not h["meta_description"]: add("High","SEO","Missing meta description.")
    if h["headings"]["h1"]==0: add("Medium","SEO","No H1 heading detected.")
    if h["headings"]["h1"]>1: add("Low","SEO","Multiple H1 headings detected.")
    if not h["canonical"]: add("Medium","SEO","Canonical URL not detected.")
    if h["images_without_alt"]: add("High","Accessibility",f"{len(h['images_without_alt'])} images appear to be missing alt text.")
    if h["unlabeled_form_controls"]: add("High","Accessibility",f"{h['unlabeled_form_controls']} form controls may lack accessible labels.")
    if not h["viewport"]: add("High","Mobile","Viewport meta tag is missing.")
    if not h["language"]: add("Low","Accessibility","HTML language attribute is missing.")
    if not sec["https"]: add("Critical","Security","Website is not using HTTPS.")
    for x in ("content-security-policy","strict-transport-security","x-content-type-options","x-frame-options"):
        if not sec["headers"][x]["present"]: add("Medium","Security",f"Missing security header: {x}.")
    if h["mixed_content"]: add("High","Security",f"{len(h['mixed_content'])} HTTP resources found on an HTTPS page.")
    if h["page_size_kb"]>3000: add("High","Performance",f"Initial HTML document is {h['page_size_kb']} KB.")
    if h["scripts"]>30: add("Medium","Performance",f"{h['scripts']} external JavaScript files detected.")
    if h["images_total"]>50: add("Medium","Performance",f"{h['images_total']} images detected.")
    if res["failed"]: add("Medium","Technical",f"{res['failed']} sampled resources failed or were unreachable.")
    if res["slow_resources"]: add("Medium","Performance",f"{len(res['slow_resources'])} sampled resources took over 1 second.")
    return f

def gemini_report(url,a):
    key=st.secrets.get("GEMINI_API_KEY")
    if not key: raise RuntimeError("GEMINI_API_KEY is missing from Streamlit Secrets.")
    client=genai.Client(api_key=key)
    prompt=f"""You are a senior website auditor, technical SEO expert, performance analyst, accessibility reviewer, and security reviewer.
Analyze this PASSIVE audit data for {url}:
{json.dumps(a,indent=2,default=str)[:110000]}
Create a professional Markdown report with:
# AI Website Audit Report
## Executive Summary
## Overall Assessment
## SEO Audit
## Performance Audit
## Accessibility Audit
## Security Audit
## Technical Audit
## Mobile/Responsive Signals
## Priority Issues (table: Priority | Category | Issue | Evidence | Recommended Fix)
## Top 10 Recommendations
## What Was NOT Tested
Be accurate. Do not invent data. Do not claim a missing security header is an exploitable vulnerability.
Do not claim SQL injection, XSS, RCE, auth bypass, CSRF, etc. was found unless the evidence proves it.
This is a passive audit, not a penetration test. Do not claim LCP, CLS, FCP or Core Web Vitals were measured."""
    return client.models.generate_content(model="gemini-2.5-flash",contents=prompt).text

st.title("🔎 AI Website Auditor")
st.caption("No PageSpeed API • No Playwright • SEO • Performance • Security • Accessibility • Gemini AI")
with st.sidebar:
    st.header("Settings")
    use_gemini=st.checkbox("Generate Gemini report",True)
    check_resources=st.checkbox("Check sampled JS/CSS/images",True)
    st.info("Passive checks only. No exploitation, brute force, authentication bypass, or destructive testing.")

url_input=st.text_input("Website URL",placeholder="https://example.com")
if st.button("🚀 Run Website Audit",type="primary",use_container_width=True):
    try: url=normalize_url(url_input)
    except ValueError as e: st.error(str(e)); st.stop()
    progress=st.progress(0); status=st.empty()
    try:
        status.write("🌐 Fetching website..."); r,ft=fetch(url); progress.progress(20)
        status.write("🔍 Analyzing HTML and SEO..."); h=analyze_html(r); progress.progress(40)
        status.write("🛡️ Analyzing security..."); sec=security(r); progress.progress(55)
        status.write("🤖 Checking robots.txt and sitemap..."); s=requests.Session(); s.headers.update({"User-Agent":UA}); d=discover(r.url,s); progress.progress(65)
        status.write("⚡ Checking sampled resources..."); res=resource_audit(h) if check_resources else {"checked":0,"successful":0,"failed":0,"failed_resources":[],"average_response_time_ms":None,"slow_resources":[]}; progress.progress(80)
        a={"website":r.url,"initial_fetch_time_seconds":round(ft,3),"html":h,"security":sec,"discovery":d,"resources":res}
        a["findings"]=findings(a)
        report=gemini_report(r.url,a) if use_gemini else "Gemini report disabled."
        progress.progress(100); status.write("✅ Audit completed.")
        st.session_state["audit"]=a; st.session_state["report"]=report
    except requests.RequestException as e: st.error(f"Could not fetch the website: {e}"); st.stop()
    except Exception as e: st.error(f"Audit failed: {e}"); st.stop()

if "audit" in st.session_state:
    a=st.session_state["audit"]; h=a["html"]; res=a["resources"]; sec=a["security"]
    st.divider(); st.header("📊 Overview")
    c=st.columns(5)
    c[0].metric("HTTP Status",h["status_code"]); c[1].metric("Initial Response",f"{a['initial_fetch_time_seconds']} s")
    c[2].metric("HTML Size",f"{h['page_size_kb']} KB"); c[3].metric("Scripts",h["scripts"]); c[4].metric("Resources Checked",res["checked"])
    st.header("🚨 Findings")
    order={"Critical":0,"High":1,"Medium":2,"Low":3}
    fs=sorted(a["findings"],key=lambda x:order.get(x["severity"],99))
    if not fs: st.success("No obvious issues were detected by passive checks.")
    for x in fs: st.markdown(f"**{x['severity']}** · {x['category']} — {x['issue']}")
    tabs=st.tabs(["🤖 Gemini Report","🔍 SEO","⚡ Performance","🛡️ Security","♿ Accessibility","🧰 Technical","📦 Raw Data"])
    with tabs[0]: st.markdown(st.session_state["report"])
    with tabs[1]:
        for label,key in [("Title","title"),("Meta description","meta_description"),("Canonical","canonical"),("Robots meta","robots_meta"),("Language","language"),("Viewport","viewport")]: st.write(f"**{label}:**",h[key] or "Missing")
        st.write("**Title length:**",h["title_length"]); st.write("**Meta description length:**",h["meta_description_length"])
        st.write("**Headings:**",h["headings"]); st.write("**Images:**",h["images_total"]); st.write("**Images missing alt:**",len(h["images_without_alt"]))
        st.write("**Internal links:**",h["internal_links"]); st.write("**External links:**",h["external_links"]); st.write("**Structured data:**",h["structured_data_count"])
        st.write("**robots.txt:**","Found" if a["discovery"]["/robots.txt"].get("exists") else "Not found"); st.write("**sitemap.xml:**","Found" if a["discovery"]["/sitemap.xml"].get("exists") else "Not found")
    with tabs[2]:
        st.metric("Initial HTTP Response",f"{a['initial_fetch_time_seconds']} s"); st.metric("HTML Size",f"{h['page_size_kb']} KB")
        st.metric("Average Sampled Resource Response",f"{res['average_response_time_ms']} ms" if res["average_response_time_ms"] else "N/A")
        st.write("**Scripts:**",h["scripts"]); st.write("**Stylesheets:**",h["stylesheets"]); st.write("**Images:**",h["images_total"]); st.write("**Failed sampled resources:**",res["failed"])
        if res["slow_resources"]: st.subheader("Slow resources"); st.json(res["slow_resources"])
        st.caption("This version does not claim Core Web Vitals because it uses neither PageSpeed API nor browser automation.")
    with tabs[3]:
        st.write("**HTTPS:**","Enabled" if sec["https"] else "Not enabled")
        for name,x in sec["headers"].items(): (st.success if x["present"] else st.warning)(f"{'✓' if x['present'] else '⚠'} {name}")
        st.subheader("TLS"); st.json(sec["tls"] or {})
        st.warning("Passive configuration findings do not prove exploitability.")
    with tabs[4]:
        st.write("**Images missing alt:**",len(h["images_without_alt"])); st.write("**Unlabeled form controls:**",h["unlabeled_form_controls"])
        st.write("**Viewport:**",h["viewport"] or "Missing"); st.write("**HTML language:**",h["language"] or "Missing"); st.write("**H1:**",h["headings"]["h1"])
    with tabs[5]:
        st.json({"final_url":h["final_url"],"status":h["status_code"],"content_type":h["content_type"],"server":h["server"],"compression":h["content_encoding"],"cache_control":h["cache_control"],"etag":h["etag"],"page_size_kb":h["page_size_kb"],"scripts":h["scripts"],"stylesheets":h["stylesheets"],"forms":h["forms"],"mixed_content":h["mixed_content"],"failed_resources":res["failed_resources"]})
    with tabs[6]:
        st.json(a)
        st.download_button("⬇️ Download Audit JSON",json.dumps(a,indent=2,default=str),"website_audit.json","application/json")
