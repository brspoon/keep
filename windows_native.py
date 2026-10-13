"""Win32 private storage and bounded process containment.

No Windows API runs at import. Construction requires a local fixed NTFS volume
and elevated operator for durable flushing. Docker Desktop support remains gated.
"""
from __future__ import annotations

from contextlib import contextmanager
import ctypes as C
from ctypes import wintypes
import hashlib
import ntpath
import os
from pathlib import Path, PureWindowsPath
import re
import subprocess
import threading
import time
import uuid

from private_store import StorageError

U8=C.c_ubyte;U16=C.c_uint16;U32=C.c_uint32;I32=C.c_int32;U64=C.c_uint64;I64=C.c_int64
PTR=C.c_void_p;SIZE=C.c_size_t;BOOL=I32;HANDLE=PTR;WSTR=C.c_wchar_p
INVALID_HANDLE=C.c_void_p(-1).value
GENERIC_READ=0x80000000;GENERIC_WRITE=0x40000000;DELETE=0x10000
READ_CONTROL=0x20000;WRITE_DAC=0x40000;WRITE_OWNER=0x80000
FILE_READ_ATTRIBUTES=0x80;FILE_SHARE_READ=1;FILE_SHARE_WRITE=2
CREATE_NEW=1;OPEN_EXISTING=3;OPEN_ALWAYS=4
FILE_FLAG_OPEN_REPARSE_POINT=0x200000;FILE_FLAG_BACKUP_SEMANTICS=0x2000000
FILE_FLAG_WRITE_THROUGH=0x80000000;FILE_ATTRIBUTE_DIRECTORY=0x10;FILE_ATTRIBUTE_REPARSE_POINT=0x400
SE_FILE_OBJECT=1;OWNER_SECURITY_INFORMATION=1;DACL_SECURITY_INFORMATION=4
SE_DACL_PRESENT=4;SE_DACL_PROTECTED=0x1000
FILE_ALL_ACCESS=0x1f01ff;INHERIT_ONLY_ACE=8;INHERITED_ACE=16
DANGEROUS_FILE_RIGHTS=0x10000000|GENERIC_WRITE|DELETE|WRITE_DAC|WRITE_OWNER|0x2|0x4|0x10|0x100
DANGEROUS_ANCESTOR_RIGHTS=0x10000000|GENERIC_WRITE|DELETE|WRITE_DAC|WRITE_OWNER|0x40|0x100
SYSTEM_SID='S-1-5-18';ADMIN_SID='S-1-5-32-544'
RESERVED=re.compile(r'^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$',re.I)


class SECURITY_ATTRIBUTES(C.Structure):
    _fields_=[('nLength',U32),('lpSecurityDescriptor',PTR),('bInheritHandle',BOOL)]
class FILETIME(C.Structure):
    _fields_=[('low',U32),('high',U32)]
class BY_HANDLE_FILE_INFORMATION(C.Structure):
    _fields_=[('attributes',U32),('creation',FILETIME),('access',FILETIME),('write',FILETIME),
              ('volume',U32),('sizeHigh',U32),('sizeLow',U32),('links',U32),('indexHigh',U32),('indexLow',U32)]
class ACL(C.Structure):
    _fields_=[('revision',U8),('sbz1',U8),('size',U16),('count',U16),('sbz2',U16)]
class ACE_HEADER(C.Structure):
    _fields_=[('type',U8),('flags',U8),('size',U16)]
class OVERLAPPED(C.Structure):
    _fields_=[('internal',SIZE),('internalHigh',SIZE),('offset',U32),('offsetHigh',U32),('event',HANDLE)]
class STARTUPINFOW(C.Structure):
    _fields_=[('cb',U32),('reserved',WSTR),('desktop',WSTR),('title',WSTR),('x',U32),('y',U32),
              ('xsize',U32),('ysize',U32),('xchars',U32),('ychars',U32),('fill',U32),('flags',U32),
              ('show',U16),('reserved2count',U16),('reserved2',PTR),('stdin',HANDLE),('stdout',HANDLE),('stderr',HANDLE)]
class STARTUPINFOEXW(C.Structure):
    _fields_=[('startup',STARTUPINFOW),('attributes',PTR)]
class PROCESS_INFORMATION(C.Structure):
    _fields_=[('process',HANDLE),('thread',HANDLE),('pid',U32),('tid',U32)]
class JOB_BASIC(C.Structure):
    _fields_=[('processTime',I64),('jobTime',I64),('flags',U32),('minWorking',SIZE),('maxWorking',SIZE),
              ('activeProcesses',U32),('affinity',SIZE),('priority',U32),('scheduling',U32)]
class IO_COUNTERS(C.Structure):
    _fields_=[(name,U64) for name in ('readOperations','writeOperations','otherOperations','readBytes','writeBytes','otherBytes')]
class STREAM_DATA(C.Structure):
    _fields_=[('size',I64),('name',C.c_wchar*296)]
class JOB_EXTENDED(C.Structure):
    _fields_=[('basic',JOB_BASIC),('io',IO_COUNTERS),('processMemory',SIZE),('jobMemory',SIZE),('peakProcess',SIZE),('peakJob',SIZE)]


def canonical_windows_path(value):
    """Pure lexical policy, executable cross-platform without filesystem access."""
    value=os.fspath(value)
    if (not isinstance(value,str) or not 3<=len(value)<=240 or any(ord(c)<32 for c in value)
            or '/' in value or value.startswith(('\\\\','\\??\\')) or not re.match(r'^[A-Za-z]:\\',value)):
        raise StorageError('Only canonical local Windows drive paths are allowed')
    parts=value[3:].split('\\') if len(value)>3 else []
    if any(not part or part in ('.','..') or part[-1] in ('.',' ') or any(c in part for c in ':*?<>|"')
           or RESERVED.fullmatch(part) for part in parts):
        raise StorageError('Windows path component is not allowed')
    if ntpath.normpath(value)!=value:raise StorageError('Windows path is not canonical')
    return value[0].upper()+value[1:]


def validate_aces(owner,aces,operator,*,private,protected,directory=False,ancestor=False,trusted_os=()):
    """Apply numeric SID/mask policy to parsed Win32 ACL observations."""
    trusted={operator,SYSTEM_SID,ADMIN_SID};owners=trusted|set(trusted_os)
    if owner not in (trusted if private else owners) or aces is None or len(aces)>64:
        raise StorageError('Windows owner or DACL is not trusted')
    if private and (owner!=operator or not protected):raise StorageError('Private Windows object owner/inheritance changed')
    granted=set()
    for kind,flags,mask,sid in aces:
        if type(kind) is not int or type(flags) is not int or type(mask) is not int or not isinstance(sid,str):
            raise StorageError('Windows ACE is malformed')
        if kind not in (0,1):raise StorageError('Unsupported Windows ACE type')
        if private:
            if kind!=0 or flags & (INHERITED_ACE|INHERIT_ONLY_ACE) or sid not in trusted or mask!=FILE_ALL_ACCESS:
                raise StorageError('Private Windows DACL is not exact')
            granted.add(sid)
        elif kind==0 and not flags & INHERIT_ONLY_ACE and sid not in owners:
            dangerous=DANGEROUS_ANCESTOR_RIGHTS if directory else DANGEROUS_FILE_RIGHTS
            if mask & dangerous:raise StorageError('Windows path is writable or replaceable by another principal')
    if private and granted!=trusted:raise StorageError('Private Windows DACL is missing its allowed principals')


class Win32:
    """Typed documented APIs; constructed only on Windows, never mocked as proof."""
    def __init__(self):
        if os.name!='nt':raise StorageError('Native Win32 APIs require Windows')
        self.kernel=C.WinDLL('kernel32',use_last_error=True);self.advapi=C.WinDLL('advapi32',use_last_error=True)
        def bind(dll,name,result,args):
            function=getattr(dll,name);function.restype=result;function.argtypes=args;setattr(self,name,function)
        K=self.kernel;A=self.advapi
        bind(K,'CloseHandle',BOOL,[HANDLE]);bind(K,'LocalFree',PTR,[PTR]);bind(K,'GetCurrentProcess',HANDLE,[])
        bind(K,'CreateFileW',HANDLE,[WSTR,U32,U32,PTR,U32,U32,HANDLE]);bind(K,'CreateDirectoryW',BOOL,[WSTR,PTR])
        bind(K,'GetFileInformationByHandle',BOOL,[HANDLE,C.POINTER(BY_HANDLE_FILE_INFORMATION)])
        bind(K,'FindFirstStreamW',HANDLE,[WSTR,U32,PTR,U32]);bind(K,'FindNextStreamW',BOOL,[HANDLE,PTR]);bind(K,'FindClose',BOOL,[HANDLE])
        bind(K,'GetFinalPathNameByHandleW',U32,[HANDLE,WSTR,U32,U32])
        bind(K,'GetDriveTypeW',U32,[WSTR]);bind(K,'QueryDosDeviceW',U32,[WSTR,WSTR,U32])
        bind(K,'GetVolumeInformationW',BOOL,[WSTR,WSTR,U32,C.POINTER(U32),C.POINTER(U32),C.POINTER(U32),WSTR,U32])
        bind(K,'FlushFileBuffers',BOOL,[HANDLE]);bind(K,'MoveFileExW',BOOL,[WSTR,WSTR,U32]);bind(K,'DeleteFileW',BOOL,[WSTR])
        bind(K,'ReadFile',BOOL,[HANDLE,PTR,U32,C.POINTER(U32),PTR]);bind(K,'WriteFile',BOOL,[HANDLE,PTR,U32,C.POINTER(U32),PTR])
        bind(K,'LockFileEx',BOOL,[HANDLE,U32,U32,U32,U32,C.POINTER(OVERLAPPED)])
        bind(K,'UnlockFileEx',BOOL,[HANDLE,U32,U32,U32,C.POINTER(OVERLAPPED)])
        bind(A,'OpenProcessToken',BOOL,[HANDLE,U32,C.POINTER(HANDLE)])
        bind(A,'GetTokenInformation',BOOL,[HANDLE,U32,PTR,U32,C.POINTER(U32)])
        bind(A,'LookupAccountNameW',BOOL,[WSTR,WSTR,PTR,C.POINTER(U32),WSTR,C.POINTER(U32),C.POINTER(U32)])
        bind(A,'ConvertSidToStringSidW',BOOL,[PTR,C.POINTER(WSTR)])
        bind(A,'ConvertStringSecurityDescriptorToSecurityDescriptorW',BOOL,[WSTR,U32,C.POINTER(PTR),C.POINTER(U32)])
        bind(A,'GetSecurityInfo',U32,[HANDLE,U32,U32,C.POINTER(PTR),C.POINTER(PTR),C.POINTER(PTR),C.POINTER(PTR),C.POINTER(PTR)])
        bind(A,'GetSecurityDescriptorControl',BOOL,[PTR,C.POINTER(U16),C.POINTER(U32)])
        bind(A,'GetSecurityDescriptorDacl',BOOL,[PTR,C.POINTER(BOOL),C.POINTER(PTR),C.POINTER(BOOL)])
        bind(A,'SetSecurityInfo',U32,[HANDLE,U32,U32,PTR,PTR,PTR,PTR])
        bind(A,'GetAce',BOOL,[PTR,U32,C.POINTER(PTR)])
        bind(K,'CreatePipe',BOOL,[C.POINTER(HANDLE),C.POINTER(HANDLE),PTR,U32])
        bind(K,'SetHandleInformation',BOOL,[HANDLE,U32,U32])
        bind(K,'InitializeProcThreadAttributeList',BOOL,[PTR,U32,U32,C.POINTER(SIZE)])
        bind(K,'UpdateProcThreadAttribute',BOOL,[PTR,U32,SIZE,PTR,SIZE,PTR,PTR])
        bind(K,'DeleteProcThreadAttributeList',None,[PTR])
        bind(K,'CreateJobObjectW',HANDLE,[PTR,WSTR]);bind(K,'SetInformationJobObject',BOOL,[HANDLE,U32,PTR,U32])
        bind(K,'AssignProcessToJobObject',BOOL,[HANDLE,HANDLE]);bind(K,'TerminateJobObject',BOOL,[HANDLE,U32])
        bind(K,'CreateProcessW',BOOL,[WSTR,PTR,PTR,PTR,BOOL,U32,PTR,WSTR,PTR,C.POINTER(PROCESS_INFORMATION)])
        bind(K,'ResumeThread',U32,[HANDLE]);bind(K,'TerminateProcess',BOOL,[HANDLE,U32])
        bind(K,'WaitForSingleObject',U32,[HANDLE,U32]);bind(K,'GetExitCodeProcess',BOOL,[HANDLE,C.POINTER(U32)])
        bind(K,'OpenThread',HANDLE,[U32,BOOL,U32]);bind(K,'CancelSynchronousIo',BOOL,[HANDLE])
        bind(K,'OpenProcess',HANDLE,[U32,BOOL,U32])
        bind(K,'DeviceIoControl',BOOL,[HANDLE,U32,PTR,U32,PTR,U32,C.POINTER(U32),PTR])

    @staticmethod
    def require(result,message):
        if not result:raise StorageError(message)
        return result

    def close(self,handle):
        if handle not in (None,0,INVALID_HANDLE):self.CloseHandle(handle)

    def sid(self,pointer):
        value=WSTR();self.require(self.ConvertSidToStringSidW(pointer,C.byref(value)),'Windows SID conversion failed')
        try:return value.value
        finally:self.LocalFree(C.cast(value,PTR))

    def operator(self):
        token=HANDLE();self.require(self.OpenProcessToken(self.GetCurrentProcess(),8,C.byref(token)),'Windows operator token is unavailable')
        try:
            size=U32();self.GetTokenInformation(token,1,None,0,C.byref(size))
            if not 1<=size.value<=65536:raise StorageError('Windows operator token exceeds its bound')
            data=C.create_string_buffer(size.value)
            self.require(self.GetTokenInformation(token,1,data,size,C.byref(size)),'Windows operator SID is unavailable')
            return self.sid(C.cast(data,C.POINTER(PTR))[0])
        finally:self.close(token)

    def trusted_installer(self):
        """Fixed local OS-service identity, never an app-provided trust principal."""
        sid_size=U32();domain_size=U32();kind=U32()
        self.LookupAccountNameW(None,'NT SERVICE\\TrustedInstaller',None,C.byref(sid_size),None,C.byref(domain_size),C.byref(kind))
        if not 1<=sid_size.value<=1024 or not 1<=domain_size.value<=256:raise StorageError('TrustedInstaller identity is unavailable')
        sid=C.create_string_buffer(sid_size.value);domain=C.create_unicode_buffer(domain_size.value)
        self.require(self.LookupAccountNameW(None,'NT SERVICE\\TrustedInstaller',sid,C.byref(sid_size),domain,C.byref(domain_size),C.byref(kind)),
                     'TrustedInstaller identity could not be verified')
        result=self.sid(C.cast(sid,PTR))
        if domain.value.upper()!='NT SERVICE' or not result.startswith('S-1-5-80-'):
            raise StorageError('TrustedInstaller identity is not the fixed local service')
        return result

    @contextmanager
    def security(self,operator,*,directory=False,inherit=False):
        flags='OICI' if directory else ''
        text='O:'+operator+'D:P'+''.join('(A;'+flags+';FA;;;'+sid+')' for sid in (operator,SYSTEM_SID,ADMIN_SID))
        descriptor=PTR();self.require(self.ConvertStringSecurityDescriptorToSecurityDescriptorW(text,1,C.byref(descriptor),None),
                                     'Private Windows security descriptor creation failed')
        attrs=SECURITY_ATTRIBUTES(C.sizeof(SECURITY_ATTRIBUTES),descriptor,bool(inherit))
        try:yield attrs
        finally:self.LocalFree(descriptor)

    def security_observation(self,handle):
        owner=PTR();dacl=PTR();descriptor=PTR()
        result=self.GetSecurityInfo(handle,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,
                                    C.byref(owner),None,C.byref(dacl),None,C.byref(descriptor))
        if result!=0:raise StorageError('Windows object security cannot be verified')
        try:
            control=U16();revision=U32()
            self.require(self.GetSecurityDescriptorControl(descriptor,C.byref(control),C.byref(revision)),
                         'Windows security descriptor is unavailable')
            if not owner.value or not control.value & SE_DACL_PRESENT or not dacl.value:
                raise StorageError('Windows object has an absent or NULL DACL')
            acl=C.cast(dacl,C.POINTER(ACL)).contents
            if acl.count>64:raise StorageError('Windows DACL exceeds its bound')
            aces=[]
            for number in range(acl.count):
                pointer=PTR();self.require(self.GetAce(dacl,number,C.byref(pointer)),'Windows ACE cannot be read')
                header=C.cast(pointer,C.POINTER(ACE_HEADER)).contents
                if header.type not in (0,1) or header.size<12:raise StorageError('Unsupported Windows ACE layout')
                mask=C.c_uint32.from_address(pointer.value+4).value
                aces.append((header.type,header.flags,mask,self.sid(pointer.value+8)))
            return self.sid(owner),aces,bool(control.value & SE_DACL_PROTECTED)
        finally:self.LocalFree(descriptor)

    def file_info(self,handle):
        info=BY_HANDLE_FILE_INFORMATION();self.require(self.GetFileInformationByHandle(handle,C.byref(info)),'Windows file identity is unavailable')
        if info.attributes & FILE_ATTRIBUTE_REPARSE_POINT:raise StorageError('Windows reparse points are not allowed')
        return info


class WindowsPrivatePaths:
    """Native NTFS storage with protected creation, pinned ancestors and flush.

Strong publication requires privileged local volume flushing. Missing privilege
or a flush failure is a held operation, never a silently successful commit.
"""
    def __init__(self,*,api=None):
        self.api=api or Win32();self.operator=self.api.operator();self.trusted_os_sids=(self.api.trusted_installer(),)
        self.windows_acl=self.check;self.windows_flush=self.flush_directory

    def volume(self,path):
        value=canonical_windows_path(path);root=value[:3]
        if self.api.GetDriveTypeW(root)!=3:raise StorageError('Only a local fixed Windows drive is supported')
        device=C.create_unicode_buffer(4096)
        if not self.api.QueryDosDeviceW(root[:2],device,len(device)) or not device.value.startswith('\\Device\\HarddiskVolume'):
            raise StorageError('Mapped or substituted Windows drives are not supported')
        flags=U32();filesystem=C.create_unicode_buffer(64)
        self.api.require(self.api.GetVolumeInformationW(root,None,0,None,None,C.byref(flags),filesystem,len(filesystem)),
                         'Windows volume metadata is unavailable')
        if filesystem.value!='NTFS' or not flags.value & 8:raise StorageError('Local NTFS with persistent ACLs is required')
        return value,root

    def open(self,path,*,access=READ_CONTROL|FILE_READ_ATTRIBUTES,create=OPEN_EXISTING,attrs=None,directory=False,share=3):
        value,_=self.volume(path)
        flags=FILE_FLAG_OPEN_REPARSE_POINT|(FILE_FLAG_BACKUP_SEMANTICS if directory else 0)
        if access & GENERIC_WRITE:flags|=FILE_FLAG_WRITE_THROUGH
        handle=self.api.CreateFileW(value,access,share,C.byref(attrs) if attrs is not None else None,create,flags,None)
        if handle==INVALID_HANDLE:raise StorageError('Windows path cannot be opened safely')
        try:
            info=self.api.file_info(handle)
            if bool(info.attributes & FILE_ATTRIBUTE_DIRECTORY)!=directory or not directory and info.links!=1:
                raise StorageError('Windows object type or hardlink identity is unsafe')
            final=C.create_unicode_buffer(32768)
            count=self.api.GetFinalPathNameByHandleW(handle,final,len(final),0)
            if not 1<=count<len(final) or not final.value.startswith('\\\\?\\'):
                raise StorageError('Windows final file path is unavailable')
            if ntpath.normcase(final.value[4:])!=ntpath.normcase(value):raise StorageError('Windows path resolves to another object')
            return handle
        except BaseException:self.api.close(handle);raise

    def verify(self,handle,*,private,directory=False,ancestor=False):
        owner,aces,protected=self.api.security_observation(handle)
        validate_aces(owner,aces,self.operator,private=private,protected=protected,directory=directory,
                      ancestor=ancestor,trusted_os=self.trusted_os_sids)

    def no_named_streams(self,path):
        info=STREAM_DATA();handle=self.api.FindFirstStreamW(str(path),0,C.byref(info),0)
        if handle==INVALID_HANDLE:raise StorageError('Windows file streams cannot be verified')
        try:
            count=0
            while True:
                count+=1
                if count>1 or info.name!='::$DATA':raise StorageError('Alternate Windows data streams are not allowed')
                if not self.api.FindNextStreamW(handle,C.byref(info)):
                    if C.get_last_error()!=38:raise StorageError('Windows file stream enumeration failed')
                    break
        finally:self.api.FindClose(handle)

    @contextmanager
    def ancestors(self,path):
        value=canonical_windows_path(path);parts=PureWindowsPath(value).parents;handles=[]
        try:
            for ancestor in reversed(parts):
                handle=self.open(str(ancestor),directory=True);handles.append(handle)
                self.verify(handle,private=False,directory=True,ancestor=True)
            yield
        finally:
            for handle in reversed(handles):self.api.close(handle)

    def check(self,path,*,directory=False,private=True):
        value,_=self.volume(path)
        with self.ancestors(value):
            handle=self.open(value,directory=directory)
            try:
                self.verify(handle,private=private,directory=directory)
                if private and not directory:self.no_named_streams(value)
            finally:self.api.close(handle)
        return Path(value)

    def mkdir(self,path):
        return self.create_directory(path,private_parent=True)

    def create_root(self,path):
        """Explicit local enrollment/CI bootstrap under a verified ancestor."""
        return self.create_directory(path,private_parent=False)

    def create_directory(self,path,*,private_parent):
        value=canonical_windows_path(path)
        with self.ancestors(value),self.api.security(self.operator,directory=True) as attrs:
            self.check(Path(value).parent,directory=True,private=private_parent)
            self.api.require(self.api.CreateDirectoryW(value,C.byref(attrs)),'Private Windows directory creation failed')
            self.check(value,directory=True);self.flush_directory(Path(value).parent)
        return Path(value)

    def read(self,path,*,limit=65536,private=True):
        value=canonical_windows_path(path)
        with self.ancestors(value):
            handle=self.open(value,access=GENERIC_READ|READ_CONTROL)
            try:
                self.verify(handle,private=private)
                if private:self.no_named_streams(value)
                info=self.api.file_info(handle)
                if (info.sizeHigh<<32|info.sizeLow)>limit:raise StorageError('Private Windows file exceeds its bound')
                data=bytearray();buffer=C.create_string_buffer(min(limit+1,65536));size=U32()
                while True:
                    self.api.require(self.api.ReadFile(handle,buffer,len(buffer),C.byref(size),None),'Private Windows read failed')
                    if not size.value:break
                    data.extend(buffer.raw[:size.value])
                    if len(data)>limit:raise StorageError('Private Windows file exceeds its bound')
                return bytes(data)
            finally:self.api.close(handle)

    def flush_directory(self,path):
        # Windows has no documented general directory-fsync contract. Flush the
        # fixed local NTFS volume; lack of elevation fails closed here.
        self.check(path,directory=True,private=False)
        _,root=self.volume(path)
        handle=self.api.CreateFileW('\\\\.\\'+root[:2],GENERIC_WRITE,3,None,OPEN_EXISTING,0,None)
        if handle==INVALID_HANDLE:raise StorageError('Elevated local NTFS volume flushing is required')
        try:self.api.require(self.api.FlushFileBuffers(handle),'Windows volume durability flush failed')
        finally:self.api.close(handle)

    def flush_file(self,path):
        value=canonical_windows_path(path)
        with self.ancestors(value):
            handle=self.open(value,access=GENERIC_WRITE|READ_CONTROL)
            try:self.verify(handle,private=True);self.api.require(self.api.FlushFileBuffers(handle),'Windows file durability flush failed')
            finally:self.api.close(handle)
            self.flush_directory(Path(value).parent)

    def publish(self,path,data,*,overwrite=False):
        value=canonical_windows_path(path);target=Path(value)
        if not isinstance(data,bytes):raise StorageError('Private file content must be bytes')
        self.check(target.parent,directory=True)
        pending=target.parent/('.pending-'+str(uuid.uuid4()))
        with self.ancestors(value),self.api.security(self.operator) as attrs:
            if target.exists() or target.is_symlink():
                self.check(target)
                if not overwrite:raise StorageError('Recovery records may not be overwritten')
            handle=self.open(pending,access=GENERIC_WRITE|READ_CONTROL,create=CREATE_NEW,attrs=attrs,share=0)
            try:
                self.verify(handle,private=True)
                remaining=memoryview(data)
                while remaining:
                    block=bytes(remaining[:1048576]);buffer=C.create_string_buffer(block);size=U32()
                    self.api.require(self.api.WriteFile(handle,buffer,len(block),C.byref(size),None),'Private Windows write failed')
                    if not size.value:raise StorageError('Private Windows write was incomplete')
                    remaining=remaining[size.value:]
                self.api.require(self.api.FlushFileBuffers(handle),'Windows private file flush failed')
            finally:self.api.close(handle)
            # No cross-volume copy or delayed operation; no unsupported
            # REPLACEFILE_WRITE_THROUGH flag. The protected pending DACL moves.
            self.api.require(self.api.MoveFileExW(str(pending),value,8|(1 if overwrite else 0)),
                             'Private Windows atomic publication failed')
            self.check(target);self.flush_file(target)
        # If publication/flush fails, preserve pending/current files for review.

    @contextmanager
    def native_lock(self,path,*,legacy=False):
        value=canonical_windows_path(path);self.check(Path(value).parent,directory=True,private=not legacy)
        with self.ancestors(value),self.api.security(self.operator) as attrs:
            handle=self.open(value,access=GENERIC_READ|GENERIC_WRITE|READ_CONTROL,create=OPEN_ALWAYS,attrs=attrs)
            overlapped=OVERLAPPED()
            try:
                self.verify(handle,private=not legacy)
                self.api.require(self.api.LockFileEx(handle,3,0,1,0,C.byref(overlapped)),'Another operation holds the Windows deployment lock')
                try:yield
                finally:self.api.UnlockFileEx(handle,0,1,0,C.byref(overlapped))
            finally:self.api.close(handle)


class WindowsJobProcess:
    """Direct suspended CreateProcessW with narrow inherited handles and Job.

Job membership protects ordinary Win32 descendants, not Docker daemon work,
WMI/service-mediated launches or an administrator deliberately subverting it.
"""
    def __init__(self,api,executable,argv,environment,cwd,operator):
        self.api=api;self.job=None;self.process=None;self.thread=None;self.handles=[];self.closed=False
        self.stdin=None;self.stdout=None;self.stderr=None;attributes=None;initialized=False
        if (not argv or argv[0]!=executable or not executable.lower().endswith('.exe')
                or any(not isinstance(value,str) or '\0' in value for value in argv)):
            raise StorageError('Windows executable/arguments are not pinned')
        canonical_windows_path(executable);canonical_windows_path(cwd)
        command=subprocess.list2cmdline(argv)
        if len(command)>=32767:raise StorageError('Windows command line exceeds its bound')
        if any(not isinstance(name,str) or not name or '=' in name or '\0' in name or not isinstance(value,str) or '\0' in value
               for name,value in environment.items()):raise StorageError('Windows process environment is invalid')
        env=C.create_unicode_buffer('\0'.join(name+'='+value for name,value in sorted(environment.items(),key=lambda item:item[0].upper()))+'\0')
        try:
            with api.security(operator) as attrs:
                self.job=api.CreateJobObjectW(C.byref(attrs),None)
                api.require(self.job,'Windows Job creation failed')
                limits=JOB_EXTENDED();limits.basic.flags=0x2000|8|0x200;limits.basic.activeProcesses=16;limits.jobMemory=1024**3
                api.require(api.SetInformationJobObject(self.job,9,C.byref(limits),C.sizeof(limits)),'Windows Job limits could not be applied')
            child=[]
            with api.security(operator,inherit=True) as attrs:
                for stdin in (True,False,False):
                    read=HANDLE();write=HANDLE();api.require(api.CreatePipe(C.byref(read),C.byref(write),C.byref(attrs),65536),'Windows process pipe creation failed')
                    self.handles.extend((read.value,write.value))
                    parent,child_end=(write.value,read.value) if stdin else (read.value,write.value)
                    api.require(api.SetHandleInformation(parent,1,0),'Windows parent pipe inheritance could not be disabled')
                    child.append(child_end)
                    if stdin:self.stdin=parent
                    elif self.stdout is None:self.stdout=parent
                    else:self.stderr=parent
            size=SIZE();api.InitializeProcThreadAttributeList(None,1,0,C.byref(size))
            if not 1<=size.value<=65536:raise StorageError('Windows process attribute list exceeds its bound')
            attributes=C.create_string_buffer(size.value)
            api.require(api.InitializeProcThreadAttributeList(attributes,1,0,C.byref(size)),'Windows process attributes could not be initialized');initialized=True
            handles=(HANDLE*3)(*child)
            api.require(api.UpdateProcThreadAttribute(attributes,0,0x20002,handles,C.sizeof(handles),None,None),
                        'Windows inherited handle allowlist failed')
            startup=STARTUPINFOEXW();startup.startup.cb=C.sizeof(startup);startup.startup.flags=0x100
            startup.startup.stdin,startup.startup.stdout,startup.startup.stderr=child;startup.attributes=C.cast(attributes,PTR)
            information=PROCESS_INFORMATION();line=C.create_unicode_buffer(command)
            api.require(api.CreateProcessW(executable,line,None,None,True,4|0x80000|0x400|0x8000000,
                env,cwd,C.byref(startup),C.byref(information)),'Windows suspended process creation failed')
            self.process,self.thread=information.process,information.thread
            api.require(api.AssignProcessToJobObject(self.job,self.process),'Windows process could not be contained before execution')
            if api.ResumeThread(self.thread)!=1:raise StorageError('Windows suspended process did not resume safely')
            api.close(self.thread);self.thread=None
            for handle in child:api.close(handle);self.handles.remove(handle)
        except BaseException:
            try:
                if self.process:
                    api.require(api.TerminateProcess(self.process,1),'Suspended Windows process termination failed')
                    if api.WaitForSingleObject(self.process,5000)!=0:raise StorageError('Suspended Windows process was not reaped')
            finally:self.close()
            raise
        finally:
            if initialized:api.DeleteProcThreadAttributeList(attributes)

    def poll(self):
        result=self.api.WaitForSingleObject(self.process,0)
        if result==258:return None
        if result!=0:raise StorageError('Windows process wait failed')
        code=U32();self.api.require(self.api.GetExitCodeProcess(self.process,C.byref(code)),'Windows process exit status is unavailable')
        return code.value

    def terminate_tree(self):
        if self.job:self.api.require(self.api.TerminateJobObject(self.job,1),'Windows process tree termination failed')

    def wait(self,milliseconds=5000):
        if self.api.WaitForSingleObject(self.process,milliseconds)!=0:raise StorageError('Windows process tree did not terminate in time')

    def read(self,handle,size):
        buffer=C.create_string_buffer(size);count=U32()
        if not self.api.ReadFile(handle,buffer,size,C.byref(count),None):
            if C.get_last_error() in (109,232,995):return b''
            raise StorageError('Windows process pipe read failed')
        return buffer.raw[:count.value]

    def write(self,data):
        remaining=memoryview(data)
        while remaining:
            block=bytes(remaining[:65536]);buffer=C.create_string_buffer(block);count=U32()
            self.api.require(self.api.WriteFile(self.stdin,buffer,len(block),C.byref(count),None),'Windows process pipe input failed')
            if not count.value:raise StorageError('Windows process pipe input was incomplete')
            remaining=remaining[count.value:]

    def close_stdin(self):
        if self.stdin is not None:
            self.api.close(self.stdin)
            if self.stdin in self.handles:self.handles.remove(self.stdin)
            self.stdin=None

    def cancel_threads(self,threads):
        for thread in threads:
            if thread.is_alive() and thread.native_id is not None:
                handle=self.api.OpenThread(1,False,thread.native_id)
                if handle:
                    try:self.api.CancelSynchronousIo(handle)
                    finally:self.api.close(handle)

    def close(self):
        if self.closed:return
        # Kill-on-close Job is never inherited/duplicated. Close it before parent
        # pipes so every ordinary descendant releases its inherited child pipes.
        self.api.close(self.job);self.job=None
        for handle in tuple(self.handles):self.api.close(handle)
        self.handles=[];self.api.close(self.thread);self.api.close(self.process)
        self.thread=self.process=None;self.closed=True


class WindowsBoundedRunner:
    def __init__(self,profile,*,paths=None,api=None):
        self.profile=profile;self.paths=paths or WindowsPrivatePaths(api=api);self.api=self.paths.api
        self.held=[]

    def environment(self):
        allowed=('PATH','USERPROFILE','SYSTEMROOT','WINDIR','TEMP','TMP')
        value={name:os.environ[name] for name in allowed if name in os.environ}
        value['DOCKER_CONFIG']=str(self.profile.docker_config);value['COMPOSE_DISABLE_ENV_FILE']='1'
        return value

    def run(self,plan):
        from host_engine import EngineError
        if self.held:raise EngineError('Windows transport has unfinished I/O; restart the agent for local review')
        if (type(plan.timeout) is not int or not 1<=plan.timeout<=1800 or type(plan.output_limit) is not int
                or not 1<=plan.output_limit<=1048576 or not isinstance(plan.stdin,bytes) or len(plan.stdin)>65536
                or not plan.argv or plan.argv[0]!=str(self.profile.docker_executable)):
            raise EngineError('Windows fixed command bounds or executable are invalid')
        self.paths.check(self.profile.docker_executable,private=False)
        self.paths.check(self.profile.installation,directory=True,private=False)
        if plan.artifact is not None:
            self.paths.check(plan.artifact.parent,directory=True)
            if (self.profile.state not in plan.artifact.parents or plan.artifact.exists() or plan.artifact.is_symlink()
                    or type(plan.artifact_limit) is not int or not 1<=plan.artifact_limit<=32*1024**3):
                raise EngineError('Windows Docker artifact destination is invalid')
            # The CLI may write only this protected precreated artifact. Native
            # trials must confirm its exporter truncates this inode rather than
            # recreating it with an inherited DACL; recreation fails closed.
            self.paths.publish(plan.artifact,b'')
            artifact_identity=plan.artifact.stat().st_ino
        if plan.stdin_file is not None:
            self.paths.check(plan.stdin_file)
            if (self.profile.state not in plan.stdin_file.parents or type(plan.stdin_file_limit) is not int
                    or not 1<=plan.stdin_file_limit<=4*1024**3 or plan.stdin_file.stat().st_size>plan.stdin_file_limit):
                raise EngineError('Windows Docker streaming input is invalid')
        process=None;threads=[];overflow=threading.Event();io_error=threading.Event();output=bytearray();failure=None
        try:
            process=WindowsJobProcess(self.api,str(self.profile.docker_executable),plan.argv,self.environment(),
                                      str(self.profile.installation),self.paths.operator)
            def read(handle,retained):
                total=0
                try:
                    while data:=process.read(handle,65536):
                        total+=len(data)
                        if total>plan.output_limit:overflow.set();return
                        if retained is not None:retained.extend(data)
                except StorageError:io_error.set()
            def write():
                try:
                    process.write(plan.stdin)
                    if plan.stdin_file is not None:
                        # Parent directory is private and the file identity was
                        # checked; retain a Windows handle for this entire read.
                        handle=self.paths.open(plan.stdin_file,access=GENERIC_READ|READ_CONTROL)
                        try:
                            self.paths.verify(handle,private=True);total=0
                            while data:=process.read(handle,65536):
                                total+=len(data)
                                if total>plan.stdin_file_limit:overflow.set();return
                                process.write(data)
                        finally:self.api.close(handle)
                except StorageError:io_error.set()
                finally:process.close_stdin()
            threads=[threading.Thread(target=read,args=(process.stdout,output),daemon=True),
                     threading.Thread(target=read,args=(process.stderr,None),daemon=True),threading.Thread(target=write,daemon=True)]
            for thread in threads:thread.start()
            deadline=time.monotonic()+plan.timeout
            while process.poll() is None:
                if plan.artifact is not None and (plan.artifact.exists() or plan.artifact.is_symlink()):
                    try:
                        self.paths.check(plan.artifact)
                        if plan.artifact.stat().st_size>plan.artifact_limit:overflow.set()
                    except (StorageError,OSError):overflow.set()
                if overflow.is_set() or io_error.is_set() or time.monotonic()>=deadline:
                    failure='Windows Docker transport failed or exceeded its bound';process.terminate_tree();break
                time.sleep(.01)
            process.wait()
            code=process.poll()
            # An exited root may leave descendants holding pipes. Terminate them
            # even on success before accepting output, rather than blocking EOF.
            process.terminate_tree()
            for thread in threads:thread.join(timeout=1)
            if any(thread.is_alive() for thread in threads):
                process.cancel_threads(threads)
                for thread in threads:thread.join(timeout=1)
            if failure or overflow.is_set() or io_error.is_set() or any(thread.is_alive() for thread in threads) or code:
                raise EngineError('Windows Docker command did not complete; reconcile its effects')
            if plan.artifact is not None:
                self.paths.check(plan.artifact)
                if plan.artifact.stat().st_size>plan.artifact_limit:raise EngineError('Windows Docker artifact exceeded its bound')
                if plan.artifact.stat().st_ino!=artifact_identity:raise EngineError('Windows Docker artifact identity changed')
                self.paths.flush_file(plan.artifact)
            return bytes(output)
        except StorageError as error:
            raise EngineError('Windows Docker transport failed; reconcile its effects') from error
        finally:
            if process:
                if any(thread.is_alive() for thread in threads):
                    process.cancel_threads(threads)
                    for thread in threads:thread.join(timeout=1)
                if any(thread.is_alive() for thread in threads):
                    # Cancellation does not promise synchronous completion. Do
                    # not close/reuse handles still used by I/O threads. Keep
                    # one held transport and prohibit subsequent operations.
                    self.held.append((process,threads))
                else:process.close()
