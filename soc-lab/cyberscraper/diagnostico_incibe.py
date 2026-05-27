# diagnostico_incibe.py
# Ejecutar desde cyberscraper/ con: python diagnostico_incibe.py

import requests
from bs4 import BeautifulSoup

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; CyberScraper/0.1)",
    "Accept-Language": "es-ES,es;q=0.9",
}

INDEX_URL = "https://www.incibe.es/incibe-cert/alerta-temprana/avisos"

# ── 1. Descargar el índice ──────────────────────────────────────────
print("Descargando índice...")
resp = requests.get(INDEX_URL, headers=HEADERS, timeout=15)
print(f"Status: {resp.status_code}")

soup = BeautifulSoup(resp.text, "html.parser")

# ── 2. Buscar los enlaces a advisories ─────────────────────────────
print("\n--- Todos los <a href> que contienen 'aviso' ---")
found = []
for a in soup.find_all("a", href=True):
    href = a["href"]
    if "aviso" in href.lower():
        print(f"  {href[:100]}")
        found.append(href)

print(f"\nTotal encontrados: {len(found)}")

# ── 3. Inspeccionar estructura de artículos ─────────────────────────
print("\n--- Tags <article> presentes ---")
for art in soup.find_all("article")[:3]:
    print(f"  classes: {art.get('class')}")
    links = art.find_all("a", href=True)
    for l in links[:2]:
        print(f"    link: {l['href'][:80]}")

# ── 4. Si encontramos al menos una URL, inspeccionar un advisory ────
if found:
    advisory_url = found[0]
    if advisory_url.startswith("/"):
        advisory_url = "https://www.incibe.es" + advisory_url

    print(f"\nDescargando advisory: {advisory_url}")
    resp2 = requests.get(advisory_url, headers=HEADERS, timeout=15)
    soup2 = BeautifulSoup(resp2.text, "html.parser")

    print("\n--- <h1> encontrados ---")
    for h1 in soup2.find_all("h1"):
        print(f"  class={h1.get('class')}  texto={h1.get_text(strip=True)[:80]}")

    print("\n--- <time> encontrados ---")
    for t in soup2.find_all("time"):
        print(f"  datetime={t.get('datetime')}  texto={t.get_text(strip=True)[:40]}")

    print("\n--- Headings h2/h3 (para localizar 'recursos afectados') ---")
    for h in soup2.find_all(["h2", "h3"]):
        print(f"  <{h.name}> class={h.get('class')}  texto={h.get_text(strip=True)[:60]}")

    print("\n--- Clases de <article> o <main> ---")
    for tag in ["article", "main", "section"]:
        el = soup2.find(tag)
        if el:
            print(f"  <{tag}> class={el.get('class')}")


INDEX_URL = "https://www.incibe.es/incibe-cert/alerta-temprana/avisos"

print("\n--- Enlaces dentro de <article class node--type-content-incibe-avisos> ---")
for art in soup.find_all("article", class_="node--type-content-incibe-avisos")[:5]:
    for a in art.find_all("a", href=True):
        print(f"  href={a['href']}")
        print(f"  texto={a.get_text(strip=True)[:80]}")


# Inspeccionar un advisory individual real
ADVISORY_URL = "https://www.incibe.es/incibe-cert/alerta-temprana/avisos/multiples-vulnerabilidades-en-minerva-de-mphrx"

print(f"\n\n=== Advisory individual: {ADVISORY_URL} ===")
resp3 = requests.get(ADVISORY_URL, headers=HEADERS, timeout=15)
soup3 = BeautifulSoup(resp3.text, "html.parser")

print("\n--- <h1> ---")
for h in soup3.find_all("h1"):
    print(f"  class={h.get('class')}  texto={h.get_text(strip=True)[:100]}")

print("\n--- <time> ---")
for t in soup3.find_all("time"):
    print(f"  datetime={t.get('datetime')}  texto={t.get_text(strip=True)[:60]}")

print("\n--- <article> y <main>: sus clases ---")
for tag in ["article", "main"]:
    el = soup3.find(tag)
    if el:
        print(f"  <{tag}> class={el.get('class')}")

print("\n--- Todos los h2/h3/h4 del advisory ---")
for h in soup3.find_all(["h2", "h3", "h4"]):
    print(f"  <{h.name}> class={h.get('class')}  texto={h.get_text(strip=True)[:80]}")

print("\n--- Primer <div> o <section> con texto largo (candidato a cuerpo) ---")
for el in soup3.find_all(["div", "section"]):
    texto = el.get_text(strip=True)
    if len(texto) > 300:
        print(f"  <{el.name}> class={el.get('class')}")
        print(f"  primeros 200 chars: {texto[:200]}")
        print()
        break

print("\n--- Interior del <article node--view-mode-full> ---")
art = soup3.find("article", class_="node--view-mode-full")
if art:
    # Clases de todos los divs directos
    for div in art.find_all("div", recursive=False):
        print(f"  <div> class={div.get('class')}")
    
    # Buscar fechas en cualquier formato dentro del article
    print("\n--- Texto que contenga fecha en el article ---")
    full_text = art.get_text(separator="\n", strip=True)
    for line in full_text.split("\n"):
        line = line.strip()
        if line and any(x in line.lower() for x in ["fecha", "publicad", "2024", "2025", "2026"]):
            print(f"  {line[:120]}")
    
    # Primeros 800 chars del texto completo del article
    print("\n--- Texto completo del article (primeros 800 chars) ---")
    print(full_text[:800])
else:
    print("  No encontrado")
