# OSINT Enum
Herramienta en Python para realizar enumeración pasiva y activa sobre un dominio y generar un informe en Markdown (`reporte.md`) con tablas limpias.


## ¿Qué hace?
- Enumeración pasiva
  - whois del dominio (CLI).
  - DNS público (NS/MX) vía nslookup.
  - Subdominios de certificados mediante crt.sh (API pública).
  - Histórico de la web con Wayback Machine (CDX API).
  
- Enumeración activa
  - Descubrimiento de subdominios usando Sublist3r (CLI).
  - Fingerprinting del sitio principal con WhatWeb (CLI).
  - Rastreo de rutas en robots.txt.
  - Extracción de URLs desde sitemap.xml (sigue índices).
    
- Reporte
  - Genera reporte.md con secciones Pasiva y Activa y tablas:
    - Subdominio → IP
    - DNS (NS/MX)
    - URLs de sitemap
    - Top paths de robots.txt
    - Muestras de Wayback

## Uso
```
python3 osint_enum.py <dominio> [-o DIRECTORIO_SALIDA]
```

Ejemplos
```
# Usando la salida por defecto: ./salida_osint/reporte.md
python3 osint_enum.py ejemplo.com

# Especificando carpeta de salida
python3 osint_enum.py ejemplo.com -o informes/ejemplo
```

Al finalizar, verás:
```
[+] Reporte generado: informes/ejemplo/reporte.md
```

## Estructura del reporte

`reporte.md` está organizado así:

- Cabecera
  - Dominio, fecha UTC.
    
- Enumeración Pasiva
  - WHOIS: bloque de texto con el whois (hasta 15k chars).
  - DNS Público (NS / MX): tabla Tipo | Valor.
  - crt.sh (Subdominios): tabla Subdominio.
  - Wayback Machine (muestras recientes): tabla Timestamp | URL archivada.
  
- Enumeración Activa
  - Subdominios (Sublist3r ∪ crt.sh) → IP: tabla Subdominio | IP.
  - WhatWeb (fingerprinting del sitio principal): bloque de texto (hasta 15k chars).
  - robots.txt (top paths): tabla Path (Disallow).
  - sitemap.xml (URLs descubiertas): tabla URL (dedup, sigue índices).

Ejemplo de tablas 
### DNS Público (NS / MX)

| Tipo | Valor |
|------|-------|
| NS 1 | ns1.proveedor.net |
| NS 2 | ns2.proveedor.net |
| MX 1 | mail.dominio.com |

### Subdominios (Sublist3r ∪ crt.sh) → IP

| Subdominio           | IP         |
|----------------------|------------|
| api.ejemplo.com      | 203.0.113.7|

