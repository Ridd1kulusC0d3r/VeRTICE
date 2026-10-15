"""Regressions for scope, execution history, imports and the Colab workflow."""
import concurrent.futures
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.request import urlopen

from vertice.core.workspace import Workspace
from vertice.core.engine import Engine
from vertice.core.history import runs, compare
from vertice.core.importers import import_file
from vertice.collectors.base import Collector, Finding
from vertice.collectors.web_fingerprint import WebFingerprintCollector
from vertice.collectors.dns_recon import DnsReconCollector
from vertice.core.entities import make
from vertice import util

ROOT = Path(__file__).resolve().parents[1]


class Source(Collector):
    name = 'fixture'
    etypes = ('domain', 'host')
    def collect(self, entity):
        return [Finding('api.aurora.example', 'host', 'has-subdomain')]


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = Workspace.create(self.tmp.name, 'test', ['aurora.example'])
    def tearDown(self):
        self.ws.close()
        self.tmp.cleanup()
    def engine(self, source=None, **kwargs):
        engine = Engine(self.ws, selected=['pivot'], **kwargs)
        engine.collectors = [source or Source()]
        return engine

    def test_active_denies_empty_scope(self):
        self.ws.meta['scope'] = []
        with self.assertRaises(ValueError):
            Engine(self.ws, allow_active=True)
        self.assertFalse(self.ws.in_scope('anything.example'))

    def test_scope_domains_cidr_urls_and_suffix_traps(self):
        self.ws.meta['scope'] += ['192.0.2.0/24', '2001:db8::/32', '198.51.100.1']
        for value in ['a.aurora.example', 'https://api.aurora.example/path', '192.0.2.5', '2001:db8::1']:
            self.assertTrue(self.ws.in_scope(value), value)
        for value in ['aurora.example.evil.test', 'bad-aurora.example', 'evil.198.51.100.1', '203.0.113.1']:
            self.assertFalse(self.ws.in_scope(value), value)

    def test_fingerprint_excluded_from_passive(self):
        self.assertFalse(WebFingerprintCollector.passive)
        self.assertNotIn('fingerprint', Engine(self.ws).enabled_collectors())

    def test_outside_seed_never_collected(self):
        source = Source()
        with patch.object(source, 'collect') as collect:
            result = self.engine(source).run(['outside.example'])
        collect.assert_not_called()
        self.assertEqual(result['skipped_scope'], 1)

    def test_discovered_third_party_not_recursed(self):
        source = Source()
        with patch.object(source, 'collect', return_value=[Finding('thirdparty.example', 'host')]) as collect:
            self.engine(source).run(['aurora.example'], depth=3)
        self.assertEqual(collect.call_count, 1)
        self.assertIn('host:thirdparty.example', self.ws.graph.nodes)

    def test_comparison_and_dedup(self):
        first = self.engine().run(['aurora.example'])['run_id']
        second = self.engine().run(['aurora.example'])['run_id']
        diff = compare(self.ws, first, second)
        self.assertTrue(diff['comparable'])
        self.assertEqual(diff['new_observations'], [])
        self.assertEqual(len(self.ws.graph.edges), 1)
        source = Source()
        with patch.object(source, 'collect', return_value=[]):
            third = self.engine(source).run(['aurora.example'])['run_id']
        self.assertEqual(len(compare(self.ws, second, third)['not_reobserved']), 1)
        self.assertIn('host:api.aurora.example', self.ws.graph.nodes)
        edge = next(iter(self.ws.graph.edges.values()))
        hashes = {r['hash'] for r in self.ws.evidence.all()}
        self.assertIn(edge.attrs['latest_evidence'], hashes)

    def test_exception_is_not_empty_and_does_not_expose_secret(self):
        source = Source()
        with patch.object(source, 'collect', side_effect=RuntimeError('key=secret')):
            result = self.engine(source).run(['aurora.example'])
        self.assertEqual(result['errors'], 1)
        self.assertEqual(runs(self.ws)[-1]['status'], 'partial')
        self.assertNotIn('key=secret', str([dict(r) for r in self.ws.evidence.all()]))

    def test_http_failure_and_raw_redaction(self):
        class Network(Source):
            def collect(self, entity):
                util.get_json('https://provider.example/api?key=SECRET')
                return []
        with patch('urllib.request.OpenerDirector.open', side_effect=OSError('SECRET')):
            result = self.engine(Network()).run(['aurora.example'])
        self.assertEqual(result['errors'], 1)
        data = [json.loads(r['data']) for r in self.ws.evidence.all() if r['kind'] == 'raw']
        self.assertEqual(len(data), 1)
        self.assertNotIn('SECRET', json.dumps(data))

    def test_collection_budget(self):
        result = self.engine(max_tasks=1).run(['aurora.example'], depth=3)
        self.assertEqual(result['collectors_run'], 1)
        self.assertTrue(result['limited'])

    def test_concurrent_ledger_writers(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda i: self.ws.evidence.record('test', 'note', str(i), {}), range(80)))
        self.assertTrue(self.ws.evidence.verify_chain()['ok'])
        self.assertEqual(self.ws.evidence.count(), 80)

    def test_subfinder_and_nmap_import(self):
        import_file(self.ws, ROOT / 'examples/subfinder.jsonl', 'subfinder', 'aurora.example')
        import_file(self.ws, ROOT / 'examples/nmap.xml', 'nmap')
        self.assertIn('host:api.aurora.example', self.ws.graph.nodes)
        self.assertIn('service:192.0.2.10:443/tcp', self.ws.graph.nodes)
        self.assertNotIn('service:192.0.2.10:22/tcp', self.ws.graph.nodes)
        self.assertFalse(self.ws.in_scope('192.0.2.10'))
        self.assertTrue(self.ws.evidence.verify_chain()['ok'])

    def test_import_rejects_external_xml_and_accepts_nmap_doctype(self):
        path = Path(self.tmp.name) / 'input.xml'
        path.write_text('<!DOCTYPE nmaprun SYSTEM "file:///etc/passwd"><nmaprun/>')
        with self.assertRaises(ValueError):
            import_file(self.ws, path, 'nmap')
        path.write_text('<!DOCTYPE nmaprun><nmaprun/>')
        self.assertEqual(import_file(self.ws, path, 'nmap')['observations'], 0)

    def test_dns_cname_not_misclassified_as_ip(self):
        with patch.object(util, 'dns_over_https', return_value=[{'type':'CNAME','data':'cdn.example.'}]):
            findings = DnsReconCollector(self.ws).collect(make('aurora.example'))
        self.assertTrue(all(f.etype == 'host' for f in findings))

    def test_missing_requested_credential_is_visible(self):
        Engine(self.ws, selected=['shodan']).run(['aurora.example'])
        self.assertEqual(runs(self.ws)[-1]['status'], 'partial')


class RedirectTests(unittest.TestCase):
    def test_fingerprint_http_does_not_follow_redirect(self):
        visited = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                visited.append(self.path)
                self.send_response(302)
                self.send_header('Location', '/outside')
                self.end_headers()
            def log_message(self, *args): pass
        server = HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = util.http_get(f'http://127.0.0.1:{server.server_port}/', follow_redirects=False)
            self.assertEqual(result[0], 302)
            self.assertEqual(visited, ['/'])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


class NotebookTests(unittest.TestCase):
    def test_notebook_offline_cells_and_web_server(self):
        notebook = json.loads((ROOT / 'notebooks/VeRTICE_Colab.ipynb').read_text())
        with tempfile.TemporaryDirectory() as tmp:
            namespace = {'BASE':Path(tmp), 'REPO':ROOT, 'json':json, 'Path':Path}
            try:
                for cell in notebook['cells']:
                    if cell['cell_type'] != 'code': continue
                    source = ''.join(cell['source'])
                    compile(source, '<colab-cell>', 'exec')
                    if 'setup' not in cell['metadata']['tags']:
                        exec(source, namespace)
                port = namespace['PORT']
                with urlopen(f'http://127.0.0.1:{port}/graph.json') as response:
                    self.assertGreater(len(json.load(response)['nodes']), 10)
                with urlopen(f'http://127.0.0.1:{port}/') as response:
                    self.assertIn('Por que este vínculo existe?', response.read().decode())
                import zipfile
                with zipfile.ZipFile(namespace['archive']) as bundle:
                    self.assertIn('evidence.db', bundle.namelist())
                    self.assertNotIn('credentials.json', bundle.namelist())
                self.assertFalse(namespace['executar_coleta_real'])
            finally:
                if 'server' in namespace:
                    namespace['server'].shutdown()
                    namespace['server'].server_close()
                    namespace['bench_ws'].close(save=False)
