import hashlib
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('publisher', pathlib.Path(__file__).with_name('signature-publisher.py'))
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)


class FeedTransferBoundary(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.folder = pathlib.Path(self.directory.name)
        self.input = self.folder / 'signed-data.cvd'
        self.input.write_bytes(b'Synthetic official-packet transport fixture')
        self.config = {'endpoint': 'https://client.nexusaerosupply.com', 'bucket': 'nexus-scanner-signatures', 'accessKey': 'synthetic-scanner-uploader', 'secretKey': 'NEVER-LOG-SYNTHETIC-SECRET', 'region': 'us-east-1'}
        self.target = 's3://nexus-scanner-signatures/official/packets/123.tar.gz'
        self.environment = {'AWS_ACCESS_KEY_ID': self.config['accessKey'], 'AWS_SECRET_ACCESS_KEY': self.config['secretKey'], 'NEXUS_SCANNER_FEED_CREDENTIAL': json.dumps(self.config)}
        self.environ = patch.dict(os.environ, {'RUNNER_TEMP': str(self.folder)})
        self.environ.start()
        self.addCleanup(self.environ.stop)
        self.addCleanup(self.directory.cleanup)

    def test_binds_payload_and_keeps_auth_out_of_argv_environment_and_logs(self):
        with patch.object(publisher.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '200', '')) as run:
            self.assertTrue(publisher.transfer(self.config, self.environment, self.input, self.target))
        args, kwargs = run.call_args
        command = args[0]
        self.assertNotIn(self.config['secretKey'], ' '.join(command))
        self.assertNotIn(self.config['accessKey'], ' '.join(command))
        self.assertNotIn(self.config['secretKey'], kwargs['input'])
        self.assertNotIn('AWS_SECRET_ACCESS_KEY', kwargs['env'])
        self.assertNotIn('NEXUS_SCANNER_FEED_CREDENTIAL', kwargs['env'])
        self.assertIn('x-amz-content-sha256: ' + hashlib.sha256(self.input.read_bytes()).hexdigest(), command)
        self.assertIn('--http1.1', command)
        self.assertIn('Expect:', command)
        self.assertNotIn('--insecure', command)
        self.assertNotIn('--location', command)
        self.assertIn('Authorization: AWS4-HMAC-SHA256', kwargs['input'])

    def test_refuses_other_bucket_outside_prefix_and_traversal_before_network(self):
        for target in ['s3://customer-documents/official/x.cvd', 's3://nexus-scanner-signatures/private/x.cvd', 's3://nexus-scanner-signatures/official/../x.cvd']:
            with self.subTest(target=target), patch.object(publisher.subprocess, 'run') as run:
                with self.assertRaises(AssertionError):
                    publisher.transfer(self.config, self.environment, self.input, target)
                run.assert_not_called()

    def test_refuses_symlink_input_before_network(self):
        with patch.object(pathlib.Path, 'is_symlink', return_value=True), patch.object(publisher.subprocess, 'run') as run:
            with self.assertRaises(AssertionError):
                publisher.transfer(self.config, self.environment, self.input, self.target)
            run.assert_not_called()

    def test_does_not_follow_redirect_or_treat_it_as_published(self):
        with patch.object(publisher.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '302', self.config['secretKey'])):
            with self.assertRaisesRegex(RuntimeError, 'http=302') as error:
                publisher.transfer(self.config, self.environment, self.input, self.target)
        self.assertNotIn(self.config['secretKey'], str(error.exception))

    def test_suppresses_sensitive_provider_response_but_reports_safe_error_code(self):
        (self.folder / 'scanner-feed-transfer-response.xml').write_text('<Error><Code>AccessDenied</Code><Message>' + self.config['secretKey'] + '</Message></Error>')
        with patch.object(publisher.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '403', self.config['secretKey'])):
            with self.assertRaisesRegex(RuntimeError, 'AccessDenied, http=403') as error:
                publisher.transfer(self.config, self.environment, self.input, self.target)
        self.assertNotIn(self.config['secretKey'], str(error.exception))

    def test_preserves_transport_failure_and_suppresses_stderr(self):
        with patch.object(publisher.subprocess, 'run', return_value=subprocess.CompletedProcess([], 28, '000', self.config['secretKey'])):
            with self.assertRaisesRegex(RuntimeError, 'transport=28') as error:
                publisher.transfer(self.config, self.environment, self.input, self.target)
        self.assertNotIn(self.config['secretKey'], str(error.exception))

    def test_client_refuses_unapproved_endpoint_and_bucket(self):
        for change in [{'endpoint': 'https://outside.invalid'}, {'bucket': 'customer-documents'}]:
            with self.subTest(change=change), patch.dict(os.environ, {'NEXUS_SCANNER_FEED_CREDENTIAL': json.dumps({**self.config, **change})}):
                with self.assertRaises(AssertionError):
                    publisher.client()

    def test_get_uses_one_signed_request_without_range_or_redirect(self):
        target = self.folder / 'restored-state.tar.gz'
        def response(command, **kwargs):
            target.write_bytes(b'Synthetic persisted updater state')
            self.assertNotIn('--range', command)
            self.assertNotIn('--location', command)
            self.assertIn('GET', command)
            self.assertNotIn('--upload-file', command)
            self.assertIn('x-amz-content-sha256: ' + hashlib.sha256(b'').hexdigest(), command)
            return subprocess.CompletedProcess(command, 0, '200', '')
        with patch.object(publisher.subprocess, 'run', side_effect=response) as run:
            self.assertTrue(publisher.transfer(self.config, self.environment, self.target, target))
            self.assertEqual(run.call_count, 1)

    def test_only_confirmed_missing_state_can_initialize_and_403_stays_closed(self):
        target = self.folder / 'state.tar.gz'
        target.write_text('<Error><Code>NoSuchKey</Code></Error>')
        with patch.object(publisher.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '404', '')):
            self.assertFalse(publisher.transfer(self.config, self.environment, self.target, target, allow_missing=True))
        target.write_text('<Error><Code>AccessDenied</Code></Error>')
        with patch.object(publisher.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '403', '')):
            with self.assertRaisesRegex(RuntimeError, 'AccessDenied'):
                publisher.transfer(self.config, self.environment, self.target, target, allow_missing=True)

    def test_range_is_signed_and_exact_response_is_required(self):
        target = self.folder / 'range.bin'
        def response(command, **kwargs):
            target.write_bytes(b'0123456789')
            pathlib.Path(command[command.index('--dump-header') + 1]).write_text('HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-9/20\r\n\r\n')
            self.assertIn('Range: bytes=0-9', command)
            self.assertIn('SignedHeaders=host;range;x-amz-content-sha256;x-amz-date', kwargs['input'])
            self.assertNotIn(self.config['secretKey'], kwargs['input'])
            self.assertIn('120', command)
            self.assertNotIn('--insecure', command)
            return subprocess.CompletedProcess(command, 0, '206', '')
        with patch.object(publisher.subprocess, 'run', side_effect=response):
            self.assertTrue(publisher.transfer(self.config, self.environment, self.target, target, byte_range=(0,9,20)))

    def test_range_rejects_ignored_or_mismatched_partial_response(self):
        target = self.folder / 'range.bin'
        for status, header, body in [('200','bytes 0-9/20',b'0123456789'),('206','bytes 1-10/20',b'0123456789'),('206','bytes 0-9/20',b'0123')]:
            with self.subTest(status=status,header=header,bytes=len(body)):
                def response(command, **kwargs):
                    target.write_bytes(body)
                    pathlib.Path(command[command.index('--dump-header') + 1]).write_text('Content-Range: '+header+'\r\n')
                    return subprocess.CompletedProcess(command,0,status,'')
                with patch.object(publisher.subprocess,'run',side_effect=response), self.assertRaises((RuntimeError,AssertionError)):
                    publisher.transfer(self.config,self.environment,self.target,target,byte_range=(0,9,20))

    def test_range_bounds_are_checked_before_network(self):
        for spec in [(-1,9,20),(0,20,20),(0,publisher.READ_CHUNK_BYTES,publisher.CHUNK_BYTES),('0',9,20)]:
            with self.subTest(spec=spec), patch.object(publisher.subprocess,'run') as run, self.assertRaises(AssertionError):
                publisher.transfer(self.config,self.environment,self.target,self.folder/'range.bin',byte_range=spec)
            run.assert_not_called()


class ChunkPublisherTests(unittest.TestCase):
    setUp = FeedTransferBoundary.setUp
    def test_split_parts_stay_bounded_and_keys_bind_full_content(self):
        self.input.write_bytes(b"Synthetic-state-packet")
        with patch.dict(os.environ, {'GITHUB_RUN_ID': '123'}), patch.object(publisher, 'WRITE_CHUNK_BYTES', 8), patch.object(publisher, 'transfer') as transfer:
            descriptor = publisher.store_chunks(self.config, self.environment, self.input, 'state')
        self.assertEqual(sum(p['bytes'] for p in descriptor['chunks']), self.input.stat().st_size)
        self.assertTrue(all(p['bytes'] <= 8 for p in descriptor['chunks']))
        self.assertTrue(all('/state/' + descriptor['archiveSha256'] + '/' in p['key'] for p in descriptor['chunks']))
        self.assertEqual(transfer.call_count, len(descriptor['chunks']))

    def test_upload_refuses_large_request_before_network(self):
        with patch.object(publisher, 'WRITE_CHUNK_BYTES', 8), patch.object(publisher.subprocess, 'run') as run:
            with self.assertRaises(AssertionError):
                publisher.transfer(self.config, self.environment, self.input, self.target)
            run.assert_not_called()

    def test_archive_requiring_too_many_parts_is_refused_before_publication(self):
        with patch.dict(os.environ, {'GITHUB_RUN_ID': '123'}), patch.object(publisher, 'WRITE_CHUNK_BYTES', 1), patch.object(publisher, 'MAX_CHUNKS', 2), patch.object(publisher, 'transfer') as transfer:
            with self.assertRaises(AssertionError):
                publisher.store_chunks(self.config, self.environment, self.input, 'packet')
            transfer.assert_not_called()

    def test_probe_verifies_small_roundtrip_without_contacting_vendor_or_updater_state(self):
        written = []
        def roundtrip(config, env, source, target):
            if isinstance(source, pathlib.Path):
                self.assertEqual(source.stat().st_size, publisher.WRITE_CHUNK_BYTES)
                self.assertEqual(target, 's3://nexus-scanner-signatures/official/transport-check.bin')
                written.append(source.read_bytes())
            else:
                target.write_bytes(written[0])
        with patch.object(sys, 'argv', ['publisher', 'probe']), patch.object(publisher, 'client', return_value=(self.config,self.environment)), patch.object(publisher, 'transfer', side_effect=roundtrip), patch.object(publisher.subprocess, 'run') as process:
            publisher.main()
            process.assert_not_called()
        self.assertFalse((self.folder/'clamav-packet').exists())

    def test_probe_refuses_corrupted_roundtrip_before_any_vendor_request(self):
        def corrupt(config, env, source, target):
            if isinstance(target, pathlib.Path):
                target.write_bytes(b'TAMPERED')
        with patch.object(sys, 'argv', ['publisher', 'probe']), patch.object(publisher, 'client', return_value=(self.config,self.environment)), patch.object(publisher, 'transfer', side_effect=corrupt), self.assertRaises(AssertionError):
            publisher.main()

    def test_changed_part_fails_reconstruction(self):
        data = b"Synthetic-state-packet"
        digest = hashlib.sha256(data).hexdigest()
        descriptor = {'transferSchema': publisher.TRANSFER_SCHEMA, 'transferRunId': '123', 'archiveSha256': digest, 'archiveBytes': len(data), 'chunks': [{'key': 'official/chunks/123/state/' + digest + '/000.part', 'bytes': len(data), 'sha256': digest}]}
        def tamper(config, env, source, target, **kwargs):
            target.write_bytes(b'X' * len(data))
        with patch.object(publisher, 'transfer', side_effect=tamper):
            with self.assertRaises(AssertionError):
                publisher.restore_chunks(self.config, self.environment, descriptor, self.folder / 'restored.tar.gz', 'state')

    def test_sequential_ranges_reconstruct_and_verify_complete_state(self):
        data=b'Synthetic-state-packet'
        digest=hashlib.sha256(data).hexdigest()
        descriptor={'transferSchema':publisher.TRANSFER_SCHEMA,'transferRunId':'123','archiveSha256':digest,'archiveBytes':len(data),'chunks':[{'key':'official/chunks/123/state/'+digest+'/000.part','bytes':len(data),'sha256':digest}]}
        ranges=[]
        def read(config,env,source,target,byte_range):
            start,end,total=byte_range;ranges.append(byte_range)
            self.assertEqual(total,len(data));target.write_bytes(data[start:end+1])
        target=self.folder/'restored.tar.gz'
        with patch.object(publisher,'READ_CHUNK_BYTES',8),patch.object(publisher,'transfer',side_effect=read):
            publisher.restore_chunks(self.config,self.environment,descriptor,target,'state')
        self.assertEqual(target.read_bytes(),data)
        self.assertEqual(ranges,[(0,7,len(data)),(8,15,len(data)),(16,len(data)-1,len(data))])

    def test_out_of_scope_chunk_is_refused_before_network(self):
        descriptor = {'transferSchema': publisher.TRANSFER_SCHEMA, 'transferRunId': '123', 'archiveSha256': 'a' * 64, 'archiveBytes': 1, 'chunks': [{'key': 'customer-documents/private', 'bytes': 1, 'sha256': 'b' * 64}]}
        with patch.object(publisher, 'transfer') as transfer:
            with self.assertRaises(AssertionError):
                publisher.restore_chunks(self.config, self.environment, descriptor, self.folder / 'restored.tar.gz', 'state')
            transfer.assert_not_called()

    def test_state_preserves_exact_client_cooldown_without_duplicate_cvds(self):
        packet=self.folder/'clamav-packet';database=packet/'databases';database.mkdir(parents=True)
        state=b'unchanged synthetic client identity and cooldown'
        (database/'freshclam.dat').write_bytes(state)
        (database/'main.cvd').write_bytes(b'Synthetic cache; must not enter client-state archive')
        (packet/'update.log').write_text('One supported updater attempt')
        with patch.dict(os.environ,{'GITHUB_RUN_ID':'123'}),patch.object(sys,'argv',['publisher','state']),patch.object(publisher,'client',return_value=(self.config,self.environment)),patch.object(publisher,'transfer'):
            publisher.main()
        with tarfile.open(packet/'freshclam-state.tar.gz','r:gz') as archive:
            self.assertEqual(archive.getnames(),['freshclam.dat'])
            self.assertEqual(archive.extractfile('freshclam.dat').read(),state)

    def test_missing_client_state_never_publishes_an_empty_reset(self):
        packet=self.folder/'clamav-packet';(packet/'databases').mkdir(parents=True)
        (packet/'update.log').write_text('Failed before client state was available')
        with patch.object(sys,'argv',['publisher','state']),patch.object(publisher,'client',return_value=(self.config,self.environment)),patch.object(publisher,'transfer') as transfer,self.assertRaises(AssertionError):
            publisher.main()
        transfer.assert_not_called()


if __name__ == '__main__':
    unittest.main()
