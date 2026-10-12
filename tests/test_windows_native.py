"""Real Windows-only filesystem and Job tests; skipped elsewhere.

Run on a clean elevated Windows 10+/Server 2016+ x64 NTFS CI worker. Only unique
synthetic private temp fixtures and their child processes are created. This suite
requires no Docker, network, service/task installation or external integration.
It proves neither power-loss durability nor Docker Desktop end-to-end behavior.
"""
from contextlib import contextmanager
import ctypes as C
from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import uuid
import zipfile

from host_engine import BoundedRunner, EngineError, Plan
from private_store import Journal, StorageError, create_private_paths, operation_lock
import windows_native as w


@unittest.skipUnless(os.name=='nt','Requires real Windows Win32/NTFS; not native evidence on macOS')
class WindowsStorageTests(unittest.TestCase):
    def setUp(self):
        self.paths=create_private_paths()
        self.root=Path(tempfile.gettempdir()).resolve(strict=True)/('keep-maintenance-ci-'+str(uuid.uuid4()))
        # This deliberately fails when CI is not elevated: volume-flush success
        # is a native qualification gate, not a skip or assumed directory fsync.
        self.paths.create_root(self.root)

    def tearDown(self):
        shutil.rmtree(self.root)

    def test_protected_creation_readback_collision_and_atomic_replacement(self):
        path=self.root/'synthetic-config.json';self.paths.publish(path,b'first')
        self.paths.check(path);self.assertEqual(self.paths.read(path),b'first')
        before=path.stat().st_ino
        with self.assertRaises(StorageError):self.paths.publish(path,b'collision')
        self.assertEqual(self.paths.read(path),b'first')
        self.paths.publish(path,b'second',overwrite=True)
        self.assertEqual(self.paths.read(path),b'second');self.assertNotEqual(path.stat().st_ino,before)
        directory=self.paths.mkdir(self.root/'nested');self.paths.check(directory,directory=True)

    def test_named_streams_and_hardlinks_are_rejected(self):
        path=self.root/'synthetic-private';self.paths.publish(path,b'fixture')
        with Path(str(path)+':extra').open('wb') as stream:stream.write(b'synthetic')
        with self.assertRaises(StorageError):self.paths.check(path)
        Path(str(path)+':extra').unlink()
        os.link(path,self.root/'other-name')
        with self.assertRaises(StorageError):self.paths.read(path)

    def test_ancestor_and_final_junctions_are_rejected(self):
        target=self.paths.mkdir(self.root/'target')
        link=self.root/'junction'
        self.paths.mkdir(link)
        substitute=('\\??\\'+str(target)).encode('utf-16le');print_name=str(target).encode('utf-16le')
        names=substitute+b'\0\0'+print_name+b'\0\0'
        payload=struct.pack('<IHHHHHH',0xa0000003,8+len(names),0,0,len(substitute),len(substitute)+2,len(print_name))+names
        handle=self.paths.open(link,access=w.GENERIC_WRITE|w.READ_CONTROL,directory=True)
        try:
            output=w.U32();buffer=C.create_string_buffer(payload)
            self.paths.api.require(self.paths.api.DeviceIoControl(handle,0x900a4,buffer,len(payload),None,0,C.byref(output),None),
                                   'Native synthetic junction creation failed')
        finally:self.paths.api.close(handle)
        with self.assertRaises(StorageError):self.paths.check(link,directory=True)
        self.paths.publish(target/'private-file',b'fixture')
        with self.assertRaises(StorageError):self.paths.read(link/'private-file')
        link.rmdir()

    def test_broad_acl_is_rejected_from_the_actual_file_handle(self):
        path=self.root/'broad-fixture';self.paths.publish(path,b'synthetic')
        api=self.paths.api;descriptor=w.PTR()
        text='O:'+self.paths.operator+'D:P(A;;FA;;;'+self.paths.operator+')(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;WD)'
        api.require(api.ConvertStringSecurityDescriptorToSecurityDescriptorW(text,1,C.byref(descriptor),None),'CI descriptor creation failed')
        try:
            present=w.BOOL();defaulted=w.BOOL();dacl=w.PTR()
            api.require(api.GetSecurityDescriptorDacl(descriptor,C.byref(present),C.byref(dacl),C.byref(defaulted)),'CI DACL read failed')
            handle=self.paths.open(path,access=w.READ_CONTROL|w.WRITE_DAC)
            try:self.assertEqual(api.SetSecurityInfo(handle,1,0x80000004,None,None,dacl,None),0)
            finally:api.close(handle)
        finally:api.LocalFree(descriptor)
        with self.assertRaises(StorageError):self.paths.read(path)

    def test_flush_failure_cannot_acknowledge_publication(self):
        path=self.root/'flush-fixture'
        with patch.object(self.paths,'flush_directory',side_effect=StorageError('Synthetic volume flush failure')):
            with self.assertRaises(StorageError):self.paths.publish(path,b'synthetic')
        # A visible file is uncertainty, not successful durable publication.
        self.assertTrue(path.exists());self.paths.flush_file(path);self.assertEqual(self.paths.read(path),b'synthetic')

    def test_journal_hash_chain_and_independent_lock_contention(self):
        identifier=str(uuid.uuid4());journal=Journal(self.paths,self.root,identifier,'a'*64)
        journal.append('accepted');journal.append('resolving')
        self.assertEqual([row['phase'] for row in journal.records()],['accepted','resolving'])
        lock=self.root/'operation.lock';module=str(Path(w.__file__).resolve().parent)
        code='import sys;sys.path.insert(0,sys.argv[1]);from pathlib import Path;from private_store import create_private_paths,operation_lock;\ntry:\n with operation_lock(create_private_paths(),Path(sys.argv[2])):sys.exit(9)\nexcept Exception:sys.exit(0)'
        with operation_lock(self.paths,lock):
            result=subprocess.run([sys.executable,'-c',code,module,str(lock)],capture_output=True,timeout=15)
            self.assertEqual(result.returncode,0)
        original=lock.stat().st_ino
        with operation_lock(self.paths,lock):pass
        self.assertEqual(lock.stat().st_ino,original)


@unittest.skipUnless(os.name=='nt','Requires actual Windows CreateProcess/Job containment')
class WindowsJobTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Hosted Python's tool-cache ancestors allow other users to replace
        # children. Keep that production rejection: execute exact local runtime
        # bytes from a unique protected tree instead of trusting the cache ACL.
        paths=create_private_paths()
        cls.runtime_root=Path(tempfile.gettempdir()).resolve(strict=True)/('keep-job-runtime-ci-'+str(uuid.uuid4()))
        paths.create_root(cls.runtime_root)
        cls.addClassCleanup(shutil.rmtree,cls.runtime_root)
        dlls=paths.mkdir(cls.runtime_root/'DLLs')
        source_executable=Path(sys.executable).resolve(strict=True)
        source_root=Path(sys.base_prefix).resolve(strict=True)
        manifest={}

        def publish_source(source,target):
            if source.is_symlink() or not source.is_file():
                raise AssertionError('Synthetic runtime source is not a regular local file')
            data=source.read_bytes()
            if not 0<len(data)<=64*1024**2:
                raise AssertionError('Synthetic runtime source exceeds its fixture bound')
            digest=hashlib.sha256(data).hexdigest()
            paths.publish(target,data)
            if hashlib.sha256(paths.read(target,limit=len(data))).hexdigest()!=digest or source.read_bytes()!=data:
                raise AssertionError('Synthetic runtime copy changed bytes')
            manifest[str(target.relative_to(cls.runtime_root))]=digest

        cls.executable=cls.runtime_root/source_executable.name
        publish_source(source_executable,cls.executable)
        for directory,destination in ((source_root,cls.runtime_root),(source_root/'DLLs',dlls)):
            if not directory.is_dir():
                raise AssertionError('Synthetic Windows runtime DLL directory is unavailable')
            for source in sorted(directory.iterdir()):
                if source.suffix.lower() in ('.dll','.pyd'):
                    publish_source(source,destination/source.name)
        if not any(name.lower().startswith('python') and name.lower().endswith('.dll') for name in manifest):
            raise AssertionError('Synthetic Windows Python runtime DLL is unavailable')

        # An uncompressed ZIP lets Python import encodings before loading any
        # extension modules. Exclude installed packages, caches and test suites;
        # no user/site modules or network downloads enter this fixture.
        library=source_root/'Lib'
        archive=io.BytesIO()
        with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_STORED) as output:
            for source in sorted(library.rglob('*.py')):
                relative=source.relative_to(library)
                if relative.parts[0] in ('site-packages','test') or '__pycache__' in relative.parts:
                    continue
                if source.is_symlink() or not source.is_file():
                    raise AssertionError('Synthetic standard library source is not a regular file')
                data=source.read_bytes()
                if source.read_bytes()!=data:
                    raise AssertionError('Synthetic standard library source changed bytes')
                output.writestr(relative.as_posix(),data)
        library_data=archive.getvalue()
        if not 0<len(library_data)<=64*1024**2:
            raise AssertionError('Synthetic standard library exceeds its fixture bound')
        library_name='python'+str(sys.version_info.major)+str(sys.version_info.minor)+'.zip'
        paths.publish(cls.runtime_root/library_name,library_data)
        if paths.read(cls.runtime_root/library_name,limit=len(library_data))!=library_data:
            raise AssertionError('Synthetic standard library copy changed bytes')
        manifest[library_name]=hashlib.sha256(library_data).hexdigest()
        # _pth isolates module loading from PYTHONHOME, PYTHONPATH, the registry
        # and the original mutable tool cache. Do not enable import site.
        path_config=cls.runtime_root/(cls.executable.stem+'._pth')
        path_data=(library_name+'\nDLLs\n.\n').encode('ascii')
        paths.publish(path_config,path_data)
        if paths.read(path_config)!=path_data:
            raise AssertionError('Synthetic runtime module configuration changed bytes')
        manifest[path_config.name]=hashlib.sha256(path_data).hexdigest()
        for module in ('host_engine','private_store','maintenance_protocol','windows_native'):
            publish_source(Path(w.__file__).resolve().parent/(module+'.py'),cls.runtime_root/(module+'.py'))
        paths.publish(cls.runtime_root/'runtime-sha256.json',json.dumps(manifest,sort_keys=True).encode('ascii'))
        paths.check(cls.executable,private=False)
        probe='import ctypes,json,pathlib,subprocess,sys,host_engine;print(json.dumps({"executable":sys.executable,"paths":sys.path,"isolated":sys.flags.isolated,"ignore_environment":sys.flags.ignore_environment,"helper":host_engine.__file__}))'
        result=subprocess.run([str(cls.executable),'-c',probe],cwd=cls.runtime_root,capture_output=True,timeout=15)
        if result.returncode:
            raise AssertionError('Protected synthetic runtime failed its native import probe: '+result.stderr.decode('utf-8','replace'))
        observed=json.loads(result.stdout)
        if (Path(observed['executable']).resolve()!=cls.executable or observed['isolated']!=1
                or observed['ignore_environment']!=1 or Path(observed['helper']).parent!=cls.runtime_root
                or any(cls.runtime_root not in (Path(value),*Path(value).parents) for value in observed['paths'])):
            raise AssertionError('Synthetic runtime escaped its protected module tree')

    def setUp(self):
        self.paths=create_private_paths();self.root=self.paths.mkdir(self.runtime_root/('case-'+str(uuid.uuid4())))
        @dataclass
        class Profile:
            installation:Path
            state:Path
            docker_executable:Path
            docker_config:Path
        self.profile=Profile(self.root,self.root,self.executable,self.root)
        self.runner=BoundedRunner(self.profile,paths=self.paths)

    def tearDown(self):shutil.rmtree(self.root)

    def plan(self,code,*,stdin=b'',timeout=5,limit=65536):
        return Plan('synthetic Windows Python fixture',(str(self.executable),'-c',code),timeout,limit,stdin)

    def stopped(self,pid):
        handle=self.paths.api.OpenProcess(0x100000|0x1000,False,pid)
        if not handle:return
        try:self.assertEqual(self.paths.api.WaitForSingleObject(handle,5000),0,'Synthetic descendant is still alive')
        finally:self.paths.api.close(handle)

    def wait_file(self,path,seconds=5):
        end=time.monotonic()+seconds
        while not path.exists() and time.monotonic()<end:time.sleep(.02)
        self.assertTrue(path.exists(),'Synthetic child did not create its PID fixture')

    def test_real_bounded_binary_stdin_stdout_and_stderr(self):
        payload=b'\x00fixture'*8192
        code='import sys;data=sys.stdin.buffer.read();sys.stderr.buffer.write(b"diagnostic");sys.stdout.buffer.write(data)'
        self.assertEqual(self.runner.run(self.plan(code,stdin=payload)),payload)

    def test_timeout_and_output_overflow_terminate_ordinary_descendants(self):
        for overflow in (False,True):
            pidfile=self.root/('child-'+str(overflow))
            child='import time;time.sleep(60)'
            suffix='import sys;sys.stdout.buffer.write(b"x"*2000000);sys.stdout.flush();time.sleep(60)' if overflow else 'time.sleep(60)'
            code='import pathlib,subprocess,sys,time;p=subprocess.Popen([sys.executable,"-c",'+repr(child)+']);pathlib.Path('+repr(str(pidfile))+').write_text(str(p.pid));'+suffix
            with self.assertRaises(EngineError):self.runner.run(self.plan(code,timeout=1,limit=1024))
            self.wait_file(pidfile);self.stopped(int(pidfile.read_text()))

    def test_root_exit_with_child_pipe_handles_does_not_wait_for_child_lifetime(self):
        pidfile=self.root/'held-pipe-child'
        code='import pathlib,subprocess,sys;p=subprocess.Popen([sys.executable,"-c","import time;time.sleep(60)"]);pathlib.Path('+repr(str(pidfile))+').write_text(str(p.pid));print("done")'
        started=time.monotonic();self.assertEqual(self.runner.run(self.plan(code)),b'done\r\n')
        self.assertLess(time.monotonic()-started,10);self.stopped(int(pidfile.read_text()))

    def test_job_assignment_failure_never_executes_first_instruction(self):
        marker=self.root/'must-not-exist';code='from pathlib import Path;Path('+repr(str(marker))+').write_text("executed")'
        with patch.object(self.paths.api,'AssignProcessToJobObject',return_value=False):
            with self.assertRaises(EngineError):self.runner.run(self.plan(code))
        self.assertFalse(marker.exists())

    def test_parent_crash_closes_last_job_handle_and_kills_tree(self):
        childfile=self.root/'crash-child';rootfile=self.root/'crash-root'
        inner='import pathlib,subprocess,sys,time;pathlib.Path('+repr(str(rootfile))+').write_text(str(__import__("os").getpid()));p=subprocess.Popen([sys.executable,"-c","import time;time.sleep(60)"]);pathlib.Path('+repr(str(childfile))+').write_text(str(p.pid));time.sleep(60)'
        module=str(self.runtime_root)
        launcher='import sys;sys.path.insert(0,'+repr(module)+');from pathlib import Path;from types import SimpleNamespace;from private_store import create_private_paths;from host_engine import BoundedRunner,Plan;p=SimpleNamespace(installation=Path('+repr(str(self.root))+'),state=Path('+repr(str(self.root))+'),docker_executable=Path(sys.executable).resolve(),docker_config=Path('+repr(str(self.root))+'));BoundedRunner(p,paths=create_private_paths()).run(Plan("synthetic",(str(p.docker_executable),"-c",'+repr(inner)+'),120))'
        parent=subprocess.Popen([str(self.executable),'-c',launcher],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            self.wait_file(childfile);self.wait_file(rootfile)
            parent.kill();parent.communicate(timeout=10)
            self.stopped(int(rootfile.read_text()));self.stopped(int(childfile.read_text()))
        finally:
            if parent.poll() is None:parent.kill();parent.communicate(timeout=10)


if __name__=='__main__':unittest.main()
