#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import datetime
import os
import re
import socket
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urljoin

import requests
from xml.etree import ElementTree as ET

# --------------------------
# Utilidades
# --------------------------

def run_cmd(cmd):
    return subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT)

def fetch(url, timeout=12, headers=None):
    h = {"User-Agent": "Mozilla/5.0 (OSINT-Enum/1.0)"} if headers is None else headers
    r = requests.get(url, timeout=timeout, headers=h, allow_redirects=True)
    return r

def normalize_domain(d):
    d = d.strip().lower()
    d = d[4:] if d.startswith("www.") else d
    return d

def uniq(seq):
    return sorted(set([s.strip() for s in seq if s and s.strip()]))

def resolve_ip(host):
    # Devuelve primera IPv4 si existe
    infos = socket.getaddrinfo(host, None, family=socket.AF_INET)
    if len(infos) > 0:
        return infos[0][4][0]
    return ""

# --------------------------
# Pasiva
# --------------------------

def whois_info(domain):
    out = run_cmd(f"whois {domain}")
    return out

def dns_ns_mx(domain):
    ns_out = run_cmd(f"nslookup -type=ns {domain}")
    mx_out = run_cmd(f"nslookup -type=mx {domain}")

    ns = re.findall(r"nameserver = ([^\s]+)", ns_out)
    mx = re.findall(r"mail exchanger = ([^\s]+)", mx_out)
    return (uniq(ns), uniq(mx))

def crtsh_subdomains(domain, limit=500):
    # https://crt.sh/?q=%25.example.com&output=json
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    r = fetch(url, timeout=20)
    subs = []
    if r.ok and r.headers.get("content-type", "").lower().startswith("application/json"):
        # Respuesta puede contener duplicados y nombres con comodines
        data = r.json()
        for row in data[:limit]:
            name_value = row.get("name_value", "")
            for part in name_value.split("\n"):
                part = part.strip().lower()
                if part.startswith("*."):
                    part = part[2:]
                if part.endswith("." + domain) or part == domain:
                    subs.append(part)
    return uniq(subs)

def wayback_summary(domain, limit=25):
    # CDX API: timestamps + original, filtrando 200
    url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=timestamp,original,statuscode&filter=statuscode:200&limit={limit}"
    r = fetch(url, timeout=20)
    rows = []
    if r.ok:
        js = r.json()
        for item in js[1:]:
            ts, original, status = item
            rows.append({"timestamp": ts, "url": original})
    return rows

# --------------------------
# Activa
# --------------------------

def sublist3r_run(domain, tmpdir):
    out_file = Path(tmpdir) / f"{domain}_sublist3r.txt"
    cmd = f"sublist3r -d {domain} -t 50 -o {out_file}"
    _ = run_cmd(cmd)
    subs = []
    if out_file.exists():
        subs = [l.strip() for l in out_file.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip()]
    return uniq(subs)

def whatweb_scan(base_url):
    # Modo verbose para sacar plugins y versiones
    out = run_cmd(f"whatweb -v {base_url}")
    return out

def fetch_robots(domain):
    url = f"https://{domain}/robots.txt"
    r = fetch(url, timeout=12)
    paths = []
    if r.ok:
        for line in r.text.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                val = line.split(":", 1)[1].strip()
                if val:
                    paths.append(val)
    return uniq(paths)

def fetch_sitemap_urls(domain, hard_limit=2000):
    # Prueba ubicaciones tÃ­picas y sigue Ã­ndices
    candidates = [
        f"https://{domain}/sitemap.xml",
        f"https://{domain}/sitemap_index.xml",
        f"https://{domain}/sitemap/sitemap.xml",
    ]
    seen = set()
    found_urls = []

    def parse_sitemap(xml_text):
        root = ET.fromstring(xml_text)
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"
        locs = []
        for el in root.findall(f".//{ns}loc"):
            if el.text:
                locs.append(el.text.strip())
        return locs

    queue = []
    for c in candidates:
        r = fetch(c, timeout=12)
        if r.ok and "xml" in r.headers.get("content-type", "").lower():
            queue.append(c)

    while queue and len(found_urls) < hard_limit:
        cur = queue.pop(0)
        if cur in seen:
            continue
        seen.add(cur)
        r = fetch(cur, timeout=15)
        if not r.ok:
            continue
        try:
            locs = parse_sitemap(r.text)
        except ET.ParseError:
            continue

        for loc in locs:
            if loc.endswith(".xml") and domain in loc:
                if loc not in seen:
                    queue.append(loc)
            else:
                found_urls.append(loc)
            if len(found_urls) >= hard_limit:
                break

    return uniq(found_urls)

# --------------------------
# Reporte
# --------------------------

def md_table(headers, rows):
    head = "| " + " | ".join(headers) + " |"
    sep = "| " + " | ".join(["------"] * len(headers)) + " |"
    lines = [head, sep]
    for r in rows:
        lines.append("| " + " | ".join(r) + " |")
    return "\n".join(lines)

def build_report(domain, outdir, whois_txt, ns_list, mx_list, crt_subs, wb_rows,
                 active_subs, sub_ip_rows, whatweb_txt, robots_paths, sitemap_urls):
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    p = Path(outdir) / "reporte.md"

    # Secciones y tablas
    lines = []
    lines.append(f"# Reporte OSINT de dominio: {domain}")
    lines.append("")
    lines.append(f"_Generado: {now}_")
    lines.append("")
    # PASIVA
    lines.append("## EnumeraciÃ³n Pasiva")
    lines.append("")
    lines.append("### WHOIS")
    lines.append("")
    lines.append("```text")
    lines.append(whois_txt.strip()[:15000])
    lines.append("```")
    lines.append("")
    lines.append("### DNS PÃºblico (NS / MX)")
    lines.append("")
    rows_dns = []
    for i, n in enumerate(ns_list, 1):
        rows_dns.append([f"NS {i}", n])
    for i, m in enumerate(mx_list, 1):
        rows_dns.append([f"MX {i}", m])
    if rows_dns:
        lines.append(md_table(["Tipo", "Valor"], rows_dns))
    else:
        lines.append("_No se encontraron registros NS/MX._")
    lines.append("")
    lines.append("### crt.sh (Subdominios observados en certificados)")
    lines.append("")
    if crt_subs:
        lines.append(md_table(["Subdominio"], [[s] for s in crt_subs]))
    else:
        lines.append("_Sin resultados en crt.sh o sin acceso._")
    lines.append("")
    lines.append("### Wayback Machine (muestras recientes)")
    lines.append("")
    if wb_rows:
        sample = wb_rows[:20]
        lines.append(md_table(["Timestamp", "URL archivada"], [[r["timestamp"], r["url"]] for r in sample]))
    else:
        lines.append("_Sin instantÃ¡neas o sin acceso._")
    lines.append("")

    # ACTIVA
    lines.append("## EnumeraciÃ³n Activa")
    lines.append("")
    lines.append("### Subdominios (Sublist3r âˆª crt.sh) â†’ IP")
    lines.append("")
    if sub_ip_rows:
        lines.append(md_table(["Subdominio", "IP"], sub_ip_rows))
    else:
        lines.append("_No se resolvieron subdominios._")
    lines.append("")
    lines.append("### WhatWeb (fingerprinting del sitio principal)")
    lines.append("")
    lines.append("```text")
    lines.append(whatweb_txt.strip()[:15000])
    lines.append("```")
    lines.append("")
    lines.append("### robots.txt (top paths)")
    lines.append("")
    if robots_paths:
        top = robots_paths[:50]
        lines.append(md_table(["Path"], [[p] for p in top]))
    else:
        lines.append("_No se encontrÃ³ robots.txt o no lista reglas._")
    lines.append("")
    lines.append("### sitemap.xml (URLs descubiertas)")
    lines.append("")
    if sitemap_urls:
        top = sitemap_urls[:200]
        lines.append(md_table(["URL"], [[u] for u in top]))
    else:
        lines.append("_No se encontrÃ³ sitemap.xml o no contiene URLs._")
    lines.append("")

    p.write_text("\n".join(lines), encoding="utf-8")
    return str(p)

# --------------------------
# Main
# --------------------------

def main():
    ap = argparse.ArgumentParser(description="EnumeraciÃ³n OSINT (pasiva y activa) sobre un dominio y generaciÃ³n de reporte.md")
    ap.add_argument("domain", help="Dominio objetivo (ej: ejemplo.com)")
    ap.add_argument("-o", "--out", default="salida_osint", help="Directorio de salida (por defecto: salida_osint)")
    args = ap.parse_args()

    domain = normalize_domain(args.domain)
    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)

    # Base URL para whatweb
    base_url = f"https://{domain}"

    # --- Pasiva ---
    whois_txt = whois_info(domain)
    ns_list, mx_list = dns_ns_mx(domain)
    crt_subs = crtsh_subdomains(domain, limit=1000)
    wb_rows = wayback_summary(domain, limit=50)

    # --- Activa ---
    with tempfile.TemporaryDirectory() as tmpd:
        act_subs = sublist3r_run(domain, tmpd)
    # Union con crt.sh para mÃ¡s cobertura
    all_subs = uniq(list(act_subs) + list(crt_subs))
    # Resolver IPs
    sub_ip_rows = []
    for s in all_subs:
        ip = ""
        try:
            ip = resolve_ip(s)
        except Exception:
            ip = ""
        sub_ip_rows.append([s, ip if ip else ""])
    # WhatWeb en host principal
    whatweb_txt = whatweb_scan(base_url)
    # robots y sitemap
    robots_paths = fetch_robots(domain)
    sitemap_urls = fetch_sitemap_urls(domain)

    report_path = build_report(
        domain=domain,
        outdir=outdir,
        whois_txt=whois_txt,
        ns_list=ns_list,
        mx_list=mx_list,
        crt_subs=crt_subs,
        wb_rows=wb_rows,
        active_subs=all_subs,
        sub_ip_rows=sub_ip_rows,
        whatweb_txt=whatweb_txt,
        robots_paths=robots_paths,
        sitemap_urls=sitemap_urls,
    )

    print(f"[+] Reporte generado: {report_path}")

if __name__ == "__main__":
    main()
