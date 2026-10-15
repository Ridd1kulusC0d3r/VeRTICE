"""Offline imports: Subfinder JSONL and Nmap XML. Never executes scanners."""
import hashlib
import json
import base64
import re
from pathlib import Path
import xml.etree.ElementTree as ET

from .engine import Engine
from .entities import make, T_HOST, T_IP, T_SERVICE
from .history import start_run, utc
from ..collectors.base import Collector, Finding


def import_file(ws, filename, format, domain=None):
    path = Path(filename)
    if path.stat().st_size > 20 * 1024 * 1024:
        raise ValueError("Arquivo excede o limite de 20 MiB")
    content = path.read_bytes()
    pairs = []
    if format == "subfinder":
        seed = make(domain or "")
        if seed is None or seed.etype != "domain":
            raise ValueError("Subfinder exige --domain com o domínio consultado")
        for line in content.decode("utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            host = str(row.get("host", "")).strip().lower().rstrip(".")
            if not host or not (host == seed.value or host.endswith("." + seed.value)):
                raise ValueError("Host inválido ou fora do domínio informado")
            if make(host) is None:
                raise ValueError("Host inválido")
            pairs.append((seed, Finding(host, T_HOST, "has-subdomain",
                attrs={"upstream_source": row.get("source")}, raw=row)))
    elif format == "nmap":
        xml = re.sub(br"<!DOCTYPE\s+nmaprun\s*>", b"", content)
        if b"<!DOCTYPE" in xml.upper() or b"<!ENTITY" in content.upper():
            raise ValueError("XML com DTD/entidades não é aceito")
        root = ET.fromstring(xml)
        if root.tag != "nmaprun":
            raise ValueError("Raiz XML deve ser nmaprun")
        for host in root.findall("host"):
            addresses = [a.get("addr") for a in host.findall("address")
                         if a.get("addrtype") in ("ipv4", "ipv6")]
            for address in addresses:
                seed = make(address)
                if seed is None or seed.etype != T_IP:
                    raise ValueError("Endereço inválido no XML")
                for port in host.findall("ports/port"):
                    state = port.find("state")
                    if state is None or state.get("state") != "open":
                        continue
                    number = int(port.get("portid"))
                    protocol = port.get("protocol")
                    if not 0 < number < 65536 or protocol not in ("tcp", "udp", "sctp"):
                        raise ValueError("Porta/protocolo inválido")
                    service = port.find("service")
                    attrs = dict(service.attrib) if service is not None else {}
                    attrs.update(port=number, transport=protocol)
                    pairs.append((seed, Finding(f"{address}:{number}/{protocol}",
                        T_SERVICE, "exposes-service", attrs=attrs,
                        raw={"host_endtime": host.get("endtime")},
                        observed_at=_timestamp(host.get("endtime")))))
    else:
        raise ValueError("Formato não suportado")
    collector = Collector(ws)
    collector.name = "import-" + format
    eng = Engine(ws)
    eng.run_id = start_run(ws, sorted({s.value for s, _ in pairs}),
                           [collector.name], 0, False)
    ws.evidence.record(collector.name, "import-source", path.name,
        {"run_id": eng.run_id, "sha256": hashlib.sha256(content).hexdigest(),
         "bytes": len(content), "format": format,
         "body_base64": base64.b64encode(content).decode("ascii")})
    for seed, finding in pairs:
        ws.graph.add_entity(seed)
        eng._apply(seed, collector, [finding])
    ws.evidence.record("engine", "run-end", eng.run_id,
        {"run_id": eng.run_id, "status": "completed", "finished_at": utc(),
         "findings": len(pairs), "mode": "offline-import"})
    ws.save()
    return {"run_id": eng.run_id, "observations": len(pairs)}


def _timestamp(value):
    from datetime import datetime, timezone
    return datetime.fromtimestamp(int(value), timezone.utc).isoformat() if value else None
