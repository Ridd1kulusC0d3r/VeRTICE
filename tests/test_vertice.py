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


if __name__ == "__main__":
    unittest.main()
