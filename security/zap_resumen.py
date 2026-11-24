"""Resume el reporte JSON de OWASP ZAP por nivel de riesgo.

Uso: python3 zap_resumen.py <zap-report.json> <resumen.txt>
Escribe el resumen en el archivo y en la consola (stderr) e imprime en stdout
solo la cantidad de alertas de riesgo ALTO, que Jenkins usa para la política.
"""

import json
import sys

RIESGOS = {"3": "ALTO", "2": "MEDIO", "1": "BAJO", "0": "INFORMATIVO"}

reporte, salida = sys.argv[1], sys.argv[2]
with open(reporte, encoding="utf-8") as f:
    datos = json.load(f)

alertas = [a for sitio in datos.get("site", []) for a in sitio.get("alerts", [])]
alertas.sort(key=lambda a: -int(a["riskcode"]))

conteo = {nivel: 0 for nivel in RIESGOS.values()}
lineas = ["RESUMEN OWASP ZAP", "=" * 60]
for a in alertas:
    nivel = RIESGOS[a["riskcode"]]
    conteo[nivel] += 1
    urls = sorted({i["uri"] for i in a.get("instances", [])})
    lineas.append(f"[{nivel}] {a['name']} (CWE-{a.get('cweid', '?')}) - {len(urls)} URL(s)")
    for url in urls[:3]:
        lineas.append(f"      {url}")
lineas.append("=" * 60)
lineas.append(" | ".join(f"{nivel}: {n}" for nivel, n in conteo.items()))

texto = "\n".join(lineas)
with open(salida, "w", encoding="utf-8") as f:
    f.write(texto + "\n")
print(texto, file=sys.stderr)
print(conteo["ALTO"])
