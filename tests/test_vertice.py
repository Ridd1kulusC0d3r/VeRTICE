"""Testes do VÉRTICE — offline, stdlib (unittest). Usam dados sintéticos.

Rodar:  python -m unittest discover -s tests -v
"""
import os
import sqlite3
import tempfile
import unittest

from vertice.core.entities import (classify, registered_domain, normalize,
                                    make, T_DOMAIN, T_IP, T_EMAIL, T_NETBLOCK,
                                    T_ASN, T_CVE, T_HASH, T_URL)
from vertice.core.graph import Graph
from vertice.core.workspace import Workspace
from vertice.pivots.registry import pivots_for
from vertice.report.pentest_prep import build_attack_surface
from vertice.report import render_report
from vertice.demo_data import build_demo


class TestClassify(unittest.TestCase):
    def test_types(self):
        self.assertEqual(classify("exemplo.com.br"), T_DOMAIN)
        self.assertEqual(classify("192.0.2.1"), T_IP)
        self.assertEqual(classify("192.0.2.0/24"), T_NETBLOCK)
        self.assertEqual(classify("a@b.com"), T_EMAIL)
        self.assertEqual(classify("AS13335"), T_ASN)
        self.assertEqual(classify("CVE-2021-44228"), T_CVE)
        self.assertEqual(classify("https://x.com/a"), T_URL)
        self.assertEqual(classify("d41d8cd98f00b204e9800998ecf8427e"), T_HASH)
        self.assertIsNone(classify("não é entidade !!"))

    def test_refang(self):
        self.assertEqual(classify("hxxps://evil[.]com/x"), T_URL)
        self.assertEqual(classify("ns1[.]exemplo[.]com"), T_DOMAIN)

    def test_registered_domain(self):
        self.assertEqual(registered_domain("www.loja.exemplo.com.br"),
                         "exemplo.com.br")
        self.assertEqual(registered_domain("a.b.exemplo.com"), "exemplo.com")
        self.assertEqual(registered_domain("exemplo.com"), "exemplo.com")

    def test_normalize(self):
        self.assertEqual(normalize("WWW.Exemplo.COM."), "www.exemplo.com")


class TestGraph(unittest.TestCase):
    def test_dedup_and_provenance(self):
        g = Graph()
        g.add("exemplo.com", T_DOMAIN, source="crtsh")
        g.add("exemplo.com", T_DOMAIN, source="dns")  # mesmo nó, +fonte
        self.assertEqual(len(g.entities(T_DOMAIN)), 1)
        node = g.get("exemplo.com", T_DOMAIN)
        self.assertEqual(node.sources, {"crtsh", "dns"})

    def test_edges_and_roundtrip(self):
        g = Graph()
        a = g.add("exemplo.com", T_DOMAIN, source="seed")
        b = g.add("1.2.3.4", T_IP, source="dns")
        g.link(a, b, "resolves-to", source="dns")
        data = g.to_dict()
        g2 = Graph.from_dict(data)
        self.assertEqual(len(g2.nodes), 2)
        self.assertEqual(len(g2.edges), 1)


class TestPivots(unittest.TestCase):
    def test_domain_pivots(self):
        ent = make("exemplo.com")
        names = {p["service"] for p in pivots_for(ent)}
        self.assertIn("crt.sh", names)
        self.assertIn("VirusTotal", names)

    def test_cve_pivots(self):
        ent = make("CVE-2021-44228")
        names = {p["service"] for p in pivots_for(ent)}
        self.assertIn("NVD", names)


class TestEvidenceChain(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.ws = build_demo(os.path.join(self.dir, "ws"))

    def tearDown(self):
        self.ws.close()

    def test_chain_intact(self):
        res = self.ws.evidence.verify_chain()
        self.assertTrue(res["ok"])
        self.assertGreater(res["records"], 10)

    def test_tamper_detected(self):
        # adultera um registro diretamente no SQLite
        path = self.ws.evidence_path
        self.ws.evidence.close()
        conn = sqlite3.connect(path)
        conn.execute("UPDATE evidence SET subject='ADULTERADO' WHERE seq=3")
        conn.commit()
        conn.close()
        # reabre e verifica
        from vertice.core.evidence import EvidenceLedger
        self.ws.evidence = EvidenceLedger(path)
        res = self.ws.evidence.verify_chain()
        self.assertFalse(res["ok"])
        self.assertEqual(res["broken_at"], 3)


class TestAttackSurface(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.ws = build_demo(os.path.join(self.dir, "ws"))

    def tearDown(self):
        self.ws.close()

    def test_surface(self):
        s = build_attack_surface(self.ws.graph)
        self.assertGreaterEqual(s["summary"]["hosts"], 12)
        # admin/vpn/hml devem pontuar alto (nomes sensíveis)
        top = [t["host"] for t in s["targets"][:6]]
        self.assertTrue(any("admin" in h or "vpn" in h or "api" in h
                            for h in top))
        # host só-histórico não deve ser "vivo"
        self.assertNotIn("old.aurora.example", s["live_hosts"])

    def test_report_renders(self):
        html = render_report(self.ws)
        self.assertIn("VÉRTICE", html)
        self.assertIn("Cadeia de custódia", html)
        self.assertIn("aurora.example", html)
        self.assertGreater(len(html), 10000)


class TestV2Collectors(unittest.TestCase):
    def test_all_registered(self):
        import vertice.collectors as c
        for name in ("internetdb", "asn", "emailsec", "tlscert", "dorks"):
            self.assertIn(name, c.REGISTRY)

    def test_new_entity_types(self):
        from vertice.core.entities import make, T_PORT, T_VULN
        self.assertEqual(make("1.2.3.4:443", T_PORT).etype, T_PORT)
        self.assertEqual(make("CVE-2021-44228", T_VULN).etype, T_VULN)


class TestConfidence(unittest.TestCase):
    def test_corroboration(self):
        from vertice.core.graph import Graph
        g = Graph()
        g.add("exemplo.com", "domain", source="crtsh")
        n = g.add("exemplo.com", "domain", source="dns")   # 2ª fonte
        self.assertAlmostEqual(n.confidence, 0.75, places=2)
        seed = g.add("alvo.com", "domain", source="seed")
        self.assertEqual(seed.confidence, 1.0)


class TestIntel(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.ws = build_demo(os.path.join(self.dir, "ws"))

    def tearDown(self):
        self.ws.close()

    def test_surface_diff(self):
        from vertice.core.intel import surface_diff
        import copy
        old = self.ws.graph
        new = Graph.from_dict(copy.deepcopy(old.to_dict()))
        new.add("inedito.aurora.example", "host", source="crtsh")
        d = surface_diff(old, new)
        self.assertEqual(d["summary"]["added"], 1)
        self.assertIn("host:inedito.aurora.example", d["added"])

    def test_correlate_favicon_cluster(self):
        from vertice.core.intel import correlate
        clusters = correlate(self.ws.graph)
        # favicon compartilhado por >=2 hosts na demo
        self.assertTrue(any(c["count"] >= 2
                            for c in clusters["by_favicon"]))

    def test_risk_signals_vuln(self):
        from vertice.core.intel import risk_signals
        api = self.ws.graph.get("api.aurora.example", "host")
        sig = risk_signals(self.ws.graph, api.key)
        self.assertIn("CVE-2021-44228", sig["vulns"])


class TestExporters(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.ws = build_demo(os.path.join(self.dir, "ws"))

    def tearDown(self):
        self.ws.close()

    def test_all_formats(self):
        from vertice.report.exporters import export, EXPORTERS
        for fmt in EXPORTERS:
            out = export(self.ws.graph, fmt)
            self.assertIsInstance(out, str)

    def test_stix_valid(self):
        import json as _json
        from vertice.report.exporters import to_stix
        b = _json.loads(to_stix(self.ws.graph))
        self.assertEqual(b["type"], "bundle")
        types = {o["type"] for o in b["objects"]}
        self.assertIn("indicator", types)
        self.assertIn("vulnerability", types)

    def test_stix_no_injection(self):
        # garante escaping básico de aspas no pattern
        from vertice.report.exporters import to_stix
        self.ws.graph.add("a'b.exemplo.com", "domain", source="t")
        out = to_stix(self.ws.graph)
        self.assertIn("\\'", out)


class TestFarolImport(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.ws = build_demo(os.path.join(self.dir, "ws"))

    def tearDown(self):
        self.ws.close()

    def test_secret_redaction(self):
        from vertice.importers import import_farol_jsonl
        path = os.path.join(self.dir, "farol.jsonl")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write('{"type":"secret","host":"api.aurora.example",'
                     '"kind":"aws_key","value":"AKIAIOSFODNN7EXAMPLE"}\n')
            fh.write('{"type":"endpoint","host":"api.aurora.example",'
                     '"value":"https://api.aurora.example/v1/x"}\n')
        stats = import_farol_jsonl(self.ws, path)
        self.assertEqual(stats["imported"], 2)
        # o VALOR do segredo nunca pode aparecer no grafo nem no ledger
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", self.ws.graph.to_json())
        leak = any("AKIAIOSFODNN7EXAMPLE" in r["data"]
                   for r in self.ws.evidence.all())
        self.assertFalse(leak)


class TestSnapshots(unittest.TestCase):
    def test_save_and_diff(self):
        import copy
        from vertice.core.intel import surface_diff
        d = tempfile.mkdtemp()
        ws = build_demo(os.path.join(d, "ws"))
        snaps = ws.list_snapshots()
        self.assertGreaterEqual(len(snaps), 1)
        ws.graph.add("x.aurora.example", "host", source="crtsh")
        s2 = ws.save_snapshot(label="t")
        old = ws.load_snapshot(snaps[0])
        new = ws.load_snapshot(s2)
        self.assertEqual(surface_diff(old, new)["summary"]["added"], 1)
        ws.close()


if __name__ == "__main__":
    unittest.main()
