"""Isolated review regressions; no real settings, captures or cloud requests."""
import sys
import asyncio
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))
from app import llm, tshark_service
from app.api import captures, settings_api
from app.main import app


class ReviewChecks(unittest.TestCase):
    def test_untrusted_origin_cannot_read_settings(self):
        messages = []
        async def request():
            async def receive():
                return {'type': 'http.request', 'body': b'', 'more_body': False}
            async def send(message):
                messages.append(message)
            await app({'type': 'http', 'asgi': {'version': '3.0'}, 'http_version': '1.1',
                       'method': 'GET', 'scheme': 'http', 'path': '/api/settings',
                       'raw_path': b'/api/settings', 'query_string': b'', 'root_path': '',
                       'headers': [(b'host', b'127.0.0.1:8123'), (b'origin', b'https://untrusted.example')],
                       'server': ('127.0.0.1', 8123), 'client': ('127.0.0.1', 50000)}, receive, send)
        with patch.object(settings_api, 'load_settings', return_value={'llm': {'api_key': 'FAKE-REVIEW-KEY'}}):
            asyncio.run(request())
        start = next(m for m in messages if m['type'] == 'http.response.start')
        body = b''.join(m.get('body', b'') for m in messages)
        exposed = start['status'] == 200 and dict(start['headers']).get(b'access-control-allow-origin') == b'*' and b'FAKE-REVIEW-KEY' in body
        self.assertFalse(exposed, 'Arbitrary Origin can read settings including API key')
        self.assertEqual(start['status'], 403)
        self.assertNotIn(b'FAKE-REVIEW-KEY', body)

    def test_filtered_page_honors_requested_limit(self):
        requested_limits = []
        def query(sql, params):
            requested_limits.append(params[-2])
            return []
        with patch.object(captures, '_get_capture', return_value={'path': 'fake.pcap'}), \
             patch.object(captures, '_tshark_or_503', return_value='fake-tshark'), \
             patch.object(captures, 'compile_expr', return_value='tcp'), \
             patch.object(tshark_service, 'validate_display_filter', return_value=(True, '')), \
             patch.object(tshark_service, 'filtered_frame_numbers', return_value=list(range(1, 301))), \
             patch.object(captures.db, 'query', side_effect=query):
            captures.list_frames('fake', offset=0, limit=200, filter='tcp')
        self.assertEqual(requested_limits, [200], 'Filtered query silently defaults to LIMIT 100')

    def test_tshark_nonzero_exit_is_not_success(self):
        proc = MagicMock()
        proc.poll.return_value = 2
        proc.wait.return_value = 2
        proc.returncode = 2
        with patch.object(tshark_service, '_popen', return_value=proc), \
             patch.object(tshark_service, 'iter_ek_proc', return_value=iter([{'partial': True}])):
            with self.assertRaises(RuntimeError):
                list(tshark_service.iter_ek('fake', []))

    def test_ipv6_is_masked_before_cloud(self):
        for address in ('2001:db8::1234', '::1', 'fe80::abcd%12', '::ffff:192.0.2.1', '2001:db8:1:2:3:4:5:6'):
            with self.subTest(address=address):
                self.assertNotIn(address, llm.mask_text('src=' + address, True))

    def test_settings_redacted_and_empty_key_preserved(self):
        current = {'llm': {'api_key': 'FAKE-REVIEW-KEY'}}
        with patch.object(settings_api, 'load_settings', return_value=current), \
             patch.object(settings_api, 'save_settings', side_effect=lambda v: v) as save:
            response = settings_api.get_settings()
            self.assertEqual(response['llm']['api_key'], '')
            self.assertTrue(response['llm']['api_key_configured'])
            response = settings_api.put_settings(settings_api.SettingsBody(llm={'api_key': '', 'model': 'new'}))
            self.assertEqual(save.call_args.args[0]['llm']['api_key'], 'FAKE-REVIEW-KEY')
            self.assertEqual(response['llm']['api_key'], '')
        self.assertEqual(current['llm']['api_key'], 'FAKE-REVIEW-KEY')

    def test_tshark_success(self):
        proc = MagicMock()
        proc.poll.return_value = 0
        proc.wait.return_value = 0
        with patch.object(tshark_service, '_popen', return_value=proc), \
             patch.object(tshark_service, 'iter_ek_proc', return_value=iter([{'ok': True}])):
            self.assertEqual(list(tshark_service.iter_ek('fake', [])), [{'ok': True}])

    def test_installer_preserves_settings(self):
        script = (Path(__file__).resolve().parents[1] / 'packaging/PcapCheck.iss').read_text(encoding='utf-8')
        self.assertIn('Excludes: "data\\*"', script)
        self.assertIn('Flags: onlyifdoesntexist uninsneveruninstall', script)

    def test_only_etw_is_reported_as_no_capture_interface(self):
        interfaces = [{'idx': 1, 'name': 'etwdump', 'desc': 'Event Tracing for Windows (ETW) reader', 'capture': False}]
        diagnosis = tshark_service.interface_diagnostics(interfaces)
        self.assertFalse(diagnosis['capture_ready'])
        self.assertIn('Npcap', diagnosis['warning'])

    def test_npf_interface_is_usable(self):
        interfaces = [{'idx': 1, 'name': r'\\Device\\NPF_{abc}', 'desc': 'Ethernet', 'capture': True},
                      {'idx': 2, 'name': 'etwdump', 'desc': 'ETW', 'capture': False}]
        diagnosis = tshark_service.interface_diagnostics(interfaces)
        self.assertTrue(diagnosis['capture_ready'])
        self.assertEqual(diagnosis['capture_count'], 1)

    def test_ipv4_masking_works(self):
        self.assertNotIn('192.0.2.1', llm.mask_text('src=192.0.2.1', True))

    def test_disabled_ai_does_not_call_cloud(self):
        with patch.object(llm, '_chat') as chat:
            self.assertEqual(llm.generate_direct_analysis({}, [], {'llm': {'enabled': False}}), '')
            chat.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
