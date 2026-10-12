"""Portable interface/ordering tests, NOT native Windows platform evidence."""
from contextlib import contextmanager
import ctypes as C
import os
import unittest

from private_store import StorageError
import windows_native as w

OPERATOR='S-1-5-21-100-200-300-1001'


class PathACLPolicyTests(unittest.TestCase):
    def test_valid_local_paths_and_ambiguous_or_remote_paths(self):
        self.assertEqual(w.canonical_windows_path('c:\\Users\\Operator\\Keep State'),'C:\\Users\\Operator\\Keep State')
        self.assertEqual(w.canonical_windows_path('C:\\'),'C:\\')
        bad=('C:relative','C:/State','\\\\host\\share\\State','\\\\?\\C:\\State','\\\\.\\C:',
             'C:\\a\\..\\b','C:\\a\\.\\b','C:\\a\\\\b','C:\\NUL.txt','C:\\Com1','C:\\State.',
             'C:\\State ','C:\\State:secret','C:\\State\\x\0','C:\\State\\x*')
        for path in bad:
            with self.subTest(path=path),self.assertRaises(StorageError):w.canonical_windows_path(path)

    def exact(self):return [(0,0,w.FILE_ALL_ACCESS,sid) for sid in (OPERATOR,w.SYSTEM_SID,w.ADMIN_SID)]

    def test_private_acl_rejects_null_inherited_broad_missing_or_foreign_owner(self):
        w.validate_aces(OPERATOR,self.exact(),OPERATOR,private=True,protected=True)
        cases=[('S-1-1-0',self.exact(),True),(OPERATOR,None,True),(OPERATOR,self.exact(),False),
               (OPERATOR,self.exact()[:2],True),(OPERATOR,self.exact()+[(0,0,w.FILE_ALL_ACCESS,'S-1-1-0')],True),
               (OPERATOR,[(0,16,w.FILE_ALL_ACCESS,sid) for sid in (OPERATOR,w.SYSTEM_SID,w.ADMIN_SID)],True),
               (OPERATOR,[(1,0,w.FILE_ALL_ACCESS,OPERATOR)],True)]
        for owner,aces,protected in cases:
            with self.subTest(owner=owner,aces=aces),self.assertRaises(StorageError):
                w.validate_aces(owner,aces,OPERATOR,private=True,protected=protected)

    def test_ancestor_read_traverse_and_child_creation_do_not_grant_replacement(self):
        common=[(0,0,w.FILE_ALL_ACCESS,w.ADMIN_SID),(0,0,0x1200a9,'S-1-5-32-545')]
        w.validate_aces(w.ADMIN_SID,common,OPERATOR,private=False,protected=False,directory=True,ancestor=True)
        w.validate_aces(w.ADMIN_SID,common+[(0,0,4,'S-1-5-11')],OPERATOR,private=False,protected=False,directory=True,ancestor=True)
        for right in (0x40,w.WRITE_DAC,w.WRITE_OWNER,w.DELETE,w.GENERIC_WRITE):
            with self.subTest(right=right),self.assertRaises(StorageError):
                w.validate_aces(w.ADMIN_SID,common+[(0,0,right,'S-1-5-11')],OPERATOR,private=False,protected=False,directory=True,ancestor=True)
        with self.assertRaises(StorageError):
            w.validate_aces(w.ADMIN_SID,[(0,0,4,'S-1-5-11')],OPERATOR,private=False,protected=False)

    def test_pointer_and_structure_sizes_are_explicit_win64_layout(self):
        if C.sizeof(C.c_void_p)!=8:self.skipTest('Win64 ABI layout test')
        expected={'SECURITY_ATTRIBUTES':24,'STARTUPINFOW':104,'STARTUPINFOEXW':112,'PROCESS_INFORMATION':24,'JOB_EXTENDED':144}
        self.assertEqual({name:C.sizeof(getattr(w,name)) for name in expected},expected)
        self.assertEqual(C.sizeof(w.U32),4);self.assertEqual(C.sizeof(w.HANDLE),8)

    @unittest.skipIf(os.name=='nt','Native Windows construction is exercised by the separate native suite')
    def test_native_api_constructor_fails_on_non_windows_without_loading_apis(self):
        with self.assertRaises(StorageError):w.Win32()


class SequenceAPI:
    """Win32 sequence recorder, with no process/handle/OS operations."""
    def __init__(self,*,assign=True,resume=1):self.events=[];self.number=10;self.assign=assign;self.resume=resume
    require=staticmethod(w.Win32.require)
    def close(self,handle):
        if handle:self.events.append(('close',handle))
    @contextmanager
    def security(self,operator,*,directory=False,inherit=False):
        self.events.append(('security',inherit));yield w.SECURITY_ATTRIBUTES(C.sizeof(w.SECURITY_ATTRIBUTES),None,inherit)
    def CreateJobObjectW(self,attrs,name):
        self.events.append(('job',attrs._obj.bInheritHandle,name));return 1
    def SetInformationJobObject(self,job,kind,limits,size):
        value=limits._obj;self.events.append(('limits',value.basic.flags,value.basic.activeProcesses,value.jobMemory));return True
    def CreatePipe(self,read,write,attrs,size):
        read._obj.value=self.number;write._obj.value=self.number+1;self.number+=2;return True
    def SetHandleInformation(self,handle,mask,value):self.events.append(('inherit',handle,value));return True
    def InitializeProcThreadAttributeList(self,data,count,flags,size):size._obj.value=64;return data is not None
    def UpdateProcThreadAttribute(self,data,flags,kind,handles,size,previous,returned):
        self.events.append(('handlelist',tuple(handles)));return True
    def DeleteProcThreadAttributeList(self,data):self.events.append(('deleteattributes',))
    def CreateProcessW(self,exe,line,pa,ta,inherit,flags,env,cwd,startup,info):
        self.events.append(('create',exe,line.value,inherit,flags));info._obj.process=2;info._obj.thread=3;return True
    def AssignProcessToJobObject(self,job,process):self.events.append(('assign',job,process));return self.assign
    def ResumeThread(self,thread):self.events.append(('resume',thread));return self.resume
    def TerminateProcess(self,process,code):self.events.append(('terminate',process));return True
    def WaitForSingleObject(self,process,timeout):self.events.append(('wait',process));return 0


class ProcessSequenceTests(unittest.TestCase):
    def create(self,api):return w.WindowsJobProcess(api,'C:\\Tools\\docker.exe',('C:\\Tools\\docker.exe','--context','desktop-linux'),
                                                   {'SYSTEMROOT':'C:\\Windows'},'C:\\Keep',OPERATOR)
    def test_suspended_assign_then_resume_and_pipe_allowlist(self):
        api=SequenceAPI();process=self.create(api);events=[event[0] for event in api.events]
        self.assertLess(events.index('create'),events.index('assign'));self.assertLess(events.index('assign'),events.index('resume'))
        create=next(event for event in api.events if event[0]=='create')
        self.assertTrue(create[4]&4);self.assertTrue(create[4]&0x80000);self.assertFalse(create[4]&0x1000000)
        self.assertEqual(next(event for event in api.events if event[0]=='handlelist')[1],(10,13,15))
        self.assertEqual(next(event for event in api.events if event[0]=='job')[1:],(False,None))
        limits=next(event for event in api.events if event[0]=='limits')
        self.assertTrue(limits[1]&0x2000);self.assertFalse(limits[1]&(0x800|0x1000));process.close()

    def test_assignment_failure_terminates_and_reaps_before_any_resume(self):
        api=SequenceAPI(assign=False)
        with self.assertRaises(StorageError):self.create(api)
        events=[event[0] for event in api.events]
        self.assertNotIn('resume',events);self.assertIn('terminate',events);self.assertIn('wait',events)
        self.assertLess(events.index('terminate'),events.index('wait'))

    def test_unexpected_resume_count_terminates_and_reaps(self):
        for count in (0,2,0xffffffff):
            api=SequenceAPI(resume=count)
            with self.subTest(count=count),self.assertRaises(StorageError):self.create(api)
            self.assertIn('terminate',[event[0] for event in api.events])

    def test_unpinned_executable_or_embedded_nul_is_rejected_before_creation(self):
        api=SequenceAPI()
        with self.assertRaises(StorageError):w.WindowsJobProcess(api,'C:\\Tools\\docker.exe',('C:\\Other.exe',),{},'C:\\Keep',OPERATOR)
        with self.assertRaises(StorageError):w.WindowsJobProcess(api,'C:\\Tools\\docker.exe',('C:\\Tools\\docker.exe','x\0'),{},'C:\\Keep',OPERATOR)
        self.assertEqual(api.events,[])


if __name__=='__main__':unittest.main()
