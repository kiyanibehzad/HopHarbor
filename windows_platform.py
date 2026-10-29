"""Windows-only process ownership and private file primitives.

The module is importable on other hosts for contract tests. Native entry points
fail closed there. Windows objects use explicit DACLs; POSIX chmod is not used as
an access-control substitute.
"""
import contextlib
import ctypes
import ntpath
import json
import secrets
import os
from pathlib import Path
import subprocess
import threading
import time
import uuid

DWORD = ctypes.c_uint32
WORD = ctypes.c_uint16
BYTE = ctypes.c_ubyte
BOOL = ctypes.c_int32
HANDLE = ctypes.c_void_p
LPVOID = ctypes.c_void_p
SIZE_T = ctypes.c_size_t
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
FILE_ATTRIBUTE_DIRECTORY = 0x10
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
READ_CONTROL = 0x00020000
WRITE_DAC = 0x00040000
FILE_READ_ATTRIBUTES = 0x80
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 1
FILE_SHARE_WRITE = 2
OPEN_EXISTING = 3
OPEN_ALWAYS = 4
CREATE_NEW = 1
FILE_ATTRIBUTE_NORMAL = 0x80
ERROR_ALREADY_EXISTS = 183
ERROR_FILE_EXISTS = 80
ERROR_FILE_NOT_FOUND = 2
ERROR_PATH_NOT_FOUND = 3
ERROR_SHARING_VIOLATION = 32
OWNER_SECURITY_INFORMATION = 1
DACL_SECURITY_INFORMATION = 4
PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
SE_FILE_OBJECT = 1
# System-directory ownership by Windows Modules Installer is trusted, never an
# arbitrary service SID. User data itself must still be owned by the user.
TRUSTED_INSTALLER = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
PRIVILEGED_SIDS = frozenset(('S-1-5-18', 'S-1-5-32-544', TRUSTED_INSTALLER))
# Other principals may traverse/read a parent, or create a different child. They
# may not retarget, delete, change the ACL/owner or write attributes on that parent.
UNTRUSTED_PARENT_WRITE = 0x00010000 | 0x00040000 | 0x00080000 | 0x100 | 0x10 | 0x40 | 0x40000000 | 0x10000000
# These metadata rights cannot retarget a verified volume root while a strictly
# protected first child anchors its nonemptiness. Never exempt child deletion,
# security changes or generic write/all grants.
ANCHORED_ROOT_METADATA = 0x00010000 | 0x100 | 0x10


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [('nLength', DWORD), ('lpSecurityDescriptor', LPVOID), ('bInheritHandle', BOOL)]


class FILETIME(ctypes.Structure):
    _fields_ = [('dwLowDateTime', DWORD), ('dwHighDateTime', DWORD)]


class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
    _fields_ = [('dwFileAttributes', DWORD), ('ftCreationTime', FILETIME),
                ('ftLastAccessTime', FILETIME), ('ftLastWriteTime', FILETIME),
                ('dwVolumeSerialNumber', DWORD), ('nFileSizeHigh', DWORD),
                ('nFileSizeLow', DWORD), ('nNumberOfLinks', DWORD),
                ('nFileIndexHigh', DWORD), ('nFileIndexLow', DWORD)]


class ACL_SIZE_INFORMATION(ctypes.Structure):
    _fields_ = [('AceCount', DWORD), ('AclBytesInUse', DWORD), ('AclBytesFree', DWORD)]


class ACE_HEADER(ctypes.Structure):
    _fields_ = [('AceType', BYTE), ('AceFlags', BYTE), ('AceSize', WORD)]


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [('cb', DWORD), ('lpReserved', ctypes.c_wchar_p),
                ('lpDesktop', ctypes.c_wchar_p), ('lpTitle', ctypes.c_wchar_p),
                ('dwX', DWORD), ('dwY', DWORD), ('dwXSize', DWORD), ('dwYSize', DWORD),
                ('dwXCountChars', DWORD), ('dwYCountChars', DWORD),
                ('dwFillAttribute', DWORD), ('dwFlags', DWORD), ('wShowWindow', WORD),
                ('cbReserved2', WORD), ('lpReserved2', LPVOID),
                ('hStdInput', HANDLE), ('hStdOutput', HANDLE), ('hStdError', HANDLE)]


class STARTUPINFOEXW(ctypes.Structure):
    _fields_ = [('StartupInfo', STARTUPINFOW), ('lpAttributeList', LPVOID)]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [('hProcess', HANDLE), ('hThread', HANDLE), ('dwProcessId', DWORD), ('dwThreadId', DWORD)]


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [('PerProcessUserTimeLimit', ctypes.c_int64), ('PerJobUserTimeLimit', ctypes.c_int64),
                ('LimitFlags', DWORD), ('MinimumWorkingSetSize', SIZE_T),
                ('MaximumWorkingSetSize', SIZE_T), ('ActiveProcessLimit', DWORD),
                ('Affinity', SIZE_T), ('PriorityClass', DWORD), ('SchedulingClass', DWORD)]


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in
                ('ReadOperationCount', 'WriteOperationCount', 'OtherOperationCount',
                 'ReadTransferCount', 'WriteTransferCount', 'OtherTransferCount')]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [('BasicLimitInformation', JOBOBJECT_BASIC_LIMIT_INFORMATION),
                ('IoInfo', IO_COUNTERS), ('ProcessMemoryLimit', SIZE_T),
                ('JobMemoryLimit', SIZE_T), ('PeakProcessMemoryUsed', SIZE_T),
                ('PeakJobMemoryUsed', SIZE_T)]


class _API:
    def __init__(self):
        if os.name != 'nt':
            raise OSError('Windows native support is only available on Windows.')
        self.k = ctypes.WinDLL('kernel32', use_last_error=True)
        self.a = ctypes.WinDLL('advapi32', use_last_error=True)
        definitions = {
            'CloseHandle': ([HANDLE], BOOL),
            'LocalFree': ([LPVOID], LPVOID),
            'GetCurrentProcess': ([], HANDLE),
            'GetWindowsDirectoryW': ([ctypes.c_wchar_p, DWORD], DWORD),
            'GetDriveTypeW': ([ctypes.c_wchar_p], DWORD),
            'GetVolumeNameForVolumeMountPointW': ([ctypes.c_wchar_p, ctypes.c_wchar_p, DWORD], BOOL),
            'GetFinalPathNameByHandleW': ([HANDLE, ctypes.c_wchar_p, DWORD, DWORD], DWORD),
            'CompareStringOrdinal': ([ctypes.c_wchar_p, ctypes.c_int, ctypes.c_wchar_p, ctypes.c_int, BOOL], ctypes.c_int),
            'GetFileInformationByHandle': ([HANDLE, ctypes.POINTER(BY_HANDLE_FILE_INFORMATION)], BOOL),
            'CreateFileW': ([ctypes.c_wchar_p, DWORD, DWORD, ctypes.POINTER(SECURITY_ATTRIBUTES), DWORD, DWORD, HANDLE], HANDLE),
            'CreateDirectoryW': ([ctypes.c_wchar_p, ctypes.POINTER(SECURITY_ATTRIBUTES)], BOOL),
            'CreatePipe': ([ctypes.POINTER(HANDLE), ctypes.POINTER(HANDLE), ctypes.POINTER(SECURITY_ATTRIBUTES), DWORD], BOOL),
            'SetHandleInformation': ([HANDLE, DWORD, DWORD], BOOL),
            'CreateJobObjectW': ([ctypes.POINTER(SECURITY_ATTRIBUTES), ctypes.c_wchar_p], HANDLE),
            'SetInformationJobObject': ([HANDLE, ctypes.c_int, LPVOID, DWORD], BOOL),
            'AssignProcessToJobObject': ([HANDLE, HANDLE], BOOL),
            'TerminateJobObject': ([HANDLE, DWORD], BOOL),
            'InitializeProcThreadAttributeList': ([LPVOID, DWORD, DWORD, ctypes.POINTER(SIZE_T)], BOOL),
            'UpdateProcThreadAttribute': ([LPVOID, DWORD, SIZE_T, LPVOID, SIZE_T, LPVOID, ctypes.POINTER(SIZE_T)], BOOL),
            'DeleteProcThreadAttributeList': ([LPVOID], None),
            'CreateProcessW': ([ctypes.c_wchar_p, ctypes.c_wchar_p, LPVOID, LPVOID, BOOL, DWORD, LPVOID, ctypes.c_wchar_p, LPVOID, ctypes.POINTER(PROCESS_INFORMATION)], BOOL),
            'ResumeThread': ([HANDLE], DWORD),
            'TerminateProcess': ([HANDLE, DWORD], BOOL),
            'WaitForSingleObject': ([HANDLE, DWORD], DWORD),
            'GetExitCodeProcess': ([HANDLE, ctypes.POINTER(DWORD)], BOOL),
        }
        for name, (args, result) in definitions.items():
            value = getattr(self.k, name); value.argtypes = args; value.restype = result
        definitions = {
            'OpenProcessToken': ([HANDLE, DWORD, ctypes.POINTER(HANDLE)], BOOL),
            'GetTokenInformation': ([HANDLE, ctypes.c_int, LPVOID, DWORD, ctypes.POINTER(DWORD)], BOOL),
            'ConvertSidToStringSidW': ([LPVOID, ctypes.POINTER(ctypes.c_wchar_p)], BOOL),
            'ConvertStringSecurityDescriptorToSecurityDescriptorW': ([ctypes.c_wchar_p, DWORD, ctypes.POINTER(LPVOID), ctypes.POINTER(DWORD)], BOOL),
            'GetSecurityInfo': ([HANDLE, ctypes.c_int, DWORD, ctypes.POINTER(LPVOID), LPVOID, ctypes.POINTER(LPVOID), LPVOID, ctypes.POINTER(LPVOID)], DWORD),
            'GetSecurityDescriptorDacl': ([LPVOID, ctypes.POINTER(BOOL), ctypes.POINTER(LPVOID), ctypes.POINTER(BOOL)], BOOL),
            'SetSecurityInfo': ([HANDLE, ctypes.c_int, DWORD, LPVOID, LPVOID, LPVOID, LPVOID], DWORD),
            'GetAclInformation': ([LPVOID, LPVOID, DWORD, ctypes.c_int], BOOL),
            'GetAce': ([LPVOID, DWORD, ctypes.POINTER(LPVOID)], BOOL),
        }
        for name, (args, result) in definitions.items():
            value = getattr(self.a, name); value.argtypes = args; value.restype = result
        self.sid = self.current_sid()

    def fail(self, operation, code=None):
        code = ctypes.get_last_error() if code is None else code
        raise OSError(code, operation + ' failed.')

    def check(self, ok, operation):
        if not ok:
            self.fail(operation)
        return ok

    def sid_text(self, pointer):
        value = ctypes.c_wchar_p()
        self.check(self.a.ConvertSidToStringSidW(pointer, ctypes.byref(value)), 'SID conversion')
        try:
            return value.value
        finally:
            self.k.LocalFree(ctypes.cast(value, LPVOID))

    def current_sid(self):
        token = HANDLE()
        self.check(self.a.OpenProcessToken(self.k.GetCurrentProcess(), 0x0008, ctypes.byref(token)), 'Current user query')
        try:
            needed = DWORD()
            self.a.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
            if not 0 < needed.value < 65536:
                self.fail('Token user query')
            buffer = ctypes.create_string_buffer(needed.value)
            self.check(self.a.GetTokenInformation(token, 1, buffer, needed, ctypes.byref(needed)), 'Token user query')
            return self.sid_text(ctypes.cast(buffer, ctypes.POINTER(LPVOID))[0])
        finally:
            self.k.CloseHandle(token)


_api_instance = None
_api_lock = threading.Lock()


def _api():
    global _api_instance
    with _api_lock:
        if _api_instance is None:
            _api_instance = _API()
        return _api_instance


def _path(value):
    value = os.fspath(value)
    if not isinstance(value, str) or not value or '\x00' in value:
        raise ValueError('Invalid private Windows path.')
    value = value.replace('/', '\\')
    drive, tail = ntpath.splitdrive(value)
    if len(drive) != 2 or drive[1] != ':' or not drive[0].isalpha() or not tail.startswith('\\'):
        raise ValueError('Use an absolute local Windows drive path.')
    parts = tail.split('\\')[1:]
    if any(part in ('.', '..') or ':' in part or part.endswith((' ', '.')) for part in parts if part):
        raise ValueError('Ambiguous Windows path components are not allowed.')
    reserved = {'CON', 'PRN', 'AUX', 'NUL'} | {'COM%d' % i for i in range(1, 10)} | {'LPT%d' % i for i in range(1, 10)}
    if any(part.split('.')[0].upper() in reserved for part in parts if part):
        raise ValueError('Device paths are not private application files.')
    return ntpath.normpath(value)


def _native_path(path):
    return '\\\\?\\' + path


def _open_handle(path, access=READ_CONTROL | FILE_READ_ATTRIBUTES, share=FILE_SHARE_READ | FILE_SHARE_WRITE):
    a = _api()
    handle = a.k.CreateFileW(_native_path(path), access, share, None, OPEN_EXISTING,
                             FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, None)
    if handle == INVALID_HANDLE_VALUE:
        a.fail('Private path open')
    return handle


def _info(handle):
    a = _api(); info = BY_HANDLE_FILE_INFORMATION()
    a.check(a.k.GetFileInformationByHandle(handle, ctypes.byref(info)), 'File identity query')
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT:
        raise ValueError('Reparse points are not allowed in private application paths.')
    return info


def _acl(handle, private, anchored_volume_root=False):
    if private and anchored_volume_root:
        raise ValueError('Volume anchor exceptions apply only to path parents.')
    a = _api(); owner, dacl, descriptor = LPVOID(), LPVOID(), LPVOID()
    result = a.a.GetSecurityInfo(handle, SE_FILE_OBJECT,
                                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                                ctypes.byref(owner), None, ctypes.byref(dacl), None,
                                ctypes.byref(descriptor))
    if result:
        a.fail('Private ACL query', result)
    try:
        owner_sid = a.sid_text(owner)
        allowed = set(PRIVILEGED_SIDS) | {a.sid}
        owner_valid = owner_sid == a.sid if private else owner_sid in allowed
        if not owner_valid:
            raise ValueError('The private path must be owned by the expected Windows user.')
        if not dacl:
            raise ValueError('Unrestricted Windows access-control lists are not allowed.')
        sizes = ACL_SIZE_INFORMATION()
        a.check(a.a.GetAclInformation(dacl, ctypes.byref(sizes), ctypes.sizeof(sizes), 2), 'ACL size query')
        seen_user = False
        for index in range(sizes.AceCount):
            ace = LPVOID()
            a.check(a.a.GetAce(dacl, index, ctypes.byref(ace)), 'ACL entry query')
            header = ctypes.cast(ace, ctypes.POINTER(ACE_HEADER)).contents
            # Unknown/object/callback ACE types are not silently treated as safe.
            if header.AceType not in (0, 1) or header.AceSize < 12:
                raise ValueError('Unsupported private ACL entry.')
            if header.AceFlags & 0x08:  # INHERIT_ONLY_ACE does not apply here.
                continue
            sid = a.sid_text(ace.value + 8)
            mask = ctypes.cast(ace.value + 4, ctypes.POINTER(DWORD)).contents.value
            if header.AceType == 0:
                if sid == a.sid:
                    seen_user = True
                if private and sid not in allowed:
                    raise ValueError('The private file is accessible to another Windows principal.')
                parent_write = UNTRUSTED_PARENT_WRITE & ~ANCHORED_ROOT_METADATA if anchored_volume_root else UNTRUSTED_PARENT_WRITE
                if not private and sid not in allowed and mask & parent_write:
                    raise ValueError('A private path parent is writable by another Windows principal.')
        if private and not seen_user:
            raise ValueError('The current Windows user has no explicit or inherited private access.')
    finally:
        a.k.LocalFree(descriptor)


def _final_volume_path(handle):
    a = _api(); buffer = ctypes.create_unicode_buffer(32768)
    size = a.k.GetFinalPathNameByHandleW(handle, buffer, len(buffer), 1)  # VOLUME_NAME_GUID.
    if not 0 < size < len(buffer):
        a.fail('Private volume identity query')
    return buffer.value


def _same_windows_path(left, right):
    result = _api().k.CompareStringOrdinal(left, -1, right, -1, True)
    if result == 0:
        _api().fail('Private volume path comparison')
    return result == 2  # CSTR_EQUAL; use Windows ordinal casing, not Unicode folds.


def _verify_root_anchor(root_handle, root_path, child_handle, first_component):
    """Prove an actual fixed volume root retains a protected, direct child.

    MS-FSA FSCTL_SET_REPARSE_POINT rejects every nonempty directory. Callers
    retain both no-delete handles, and validate the child's unchanged strict
    parent ACL first. Exact handle paths prevent a reparse/restore race while
    opening the child. An empty root, SUBST folder or arbitrary directory is
    never an anchor.
    """
    drive, tail = ntpath.splitdrive(root_path)
    if len(drive) != 2 or tail != '\\' or not first_component or ntpath.basename(first_component) != first_component:
        raise ValueError('A protected direct child is required for a volume anchor.')
    a = _api()
    if a.k.GetDriveTypeW(root_path) != 3:  # DRIVE_FIXED, never a network/removable drive.
        raise ValueError('A private path anchor must be a fixed local volume.')
    buffer = ctypes.create_unicode_buffer(64)
    a.check(a.k.GetVolumeNameForVolumeMountPointW(root_path, buffer, len(buffer)), 'Private volume name query')
    volume = buffer.value
    prefix = '\\\\?\\Volume{'
    if not volume.casefold().startswith(prefix.casefold()) or not volume.endswith('}\\'):
        raise ValueError('Invalid private volume identity.')
    ident = volume[len(prefix):-2]
    if str(uuid.UUID(ident)) != ident.lower():
        raise ValueError('Invalid private volume identity.')
    if not _same_windows_path(_final_volume_path(root_handle), volume):
        raise ValueError('The drive path is not the actual volume root.')
    if not _same_windows_path(_final_volume_path(child_handle), volume + first_component):
        raise ValueError('The protected child is outside the actual volume root.')
    # Recheck after the exact child identity is established, closing an ABA
    # window during child open. _info rejects any newly assigned reparse tag.
    if not _info(root_handle).dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY:
        raise ValueError('The volume anchor is not a directory.')


@contextlib.contextmanager
def _parents(path):
    a = _api(); handles = []
    drive, tail = ntpath.splitdrive(path)
    components = [part for part in tail.split('\\') if part]
    parent = drive + '\\'
    root_failure = None
    try:
        for index, component in enumerate([''] + components[:-1]):
            if component:
                parent = ntpath.join(parent, component)
            handle = _open_handle(parent)
            handles.append(handle)
            if not _info(handle).dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY:
                raise ValueError('A private path parent is not a directory.')
            if index == 0:
                try:
                    _acl(handle, private=False)
                except ValueError as error:
                    root_failure = error
            else:
                _acl(handle, private=False)
                if index == 1 and root_failure is not None:
                    _verify_root_anchor(handles[0], drive + '\\', handle, component)
                    _acl(handles[0], private=False, anchored_volume_root=True)
                    root_failure = None
        if root_failure is not None:
            raise ValueError('The volume root requires an existing protected child path.') from root_failure
        yield
    finally:
        for handle in reversed(handles):
            a.k.CloseHandle(handle)


@contextlib.contextmanager
def _security(directory=False, inherit_handle=False):
    a = _api(); descriptor = LPVOID()
    inheritance = 'OICI' if directory else ''
    sddl = 'O:%sD:P(A;%s;FA;;;%s)(A;%s;FA;;;SY)(A;%s;FA;;;BA)' % (a.sid, inheritance, a.sid, inheritance, inheritance)
    a.check(a.a.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None), 'Private ACL creation')
    attributes = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), descriptor, inherit_handle)
    try:
        yield attributes, descriptor
    finally:
        a.k.LocalFree(descriptor)


def _protect(handle, directory=False):
    a = _api()
    with _security(directory) as (_attributes, descriptor):
        present, defaulted, dacl = BOOL(), BOOL(), LPVOID()
        a.check(a.a.GetSecurityDescriptorDacl(descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)), 'Private DACL query')
        if not present or not dacl:
            raise ValueError('A private DACL could not be created.')
        result = a.a.SetSecurityInfo(handle, SE_FILE_OBJECT,
                                   DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                   None, None, dacl, None)
        if result:
            a.fail('Private ACL application', result)


def ensure_private_directory(path):
    path = _path(path); a = _api()
    parent = ntpath.dirname(path)
    if parent == path:
        raise ValueError('A drive root cannot be an application data directory.')
    if not os.path.exists(parent):
        ensure_private_directory(parent)
    with _parents(path):
        with _security(directory=True) as (attributes, _descriptor):
            created = a.k.CreateDirectoryW(_native_path(path), ctypes.byref(attributes))
            if not created and ctypes.get_last_error() != ERROR_ALREADY_EXISTS:
                a.fail('Private directory creation')
        handle = _open_handle(path, READ_CONTROL | FILE_READ_ATTRIBUTES | WRITE_DAC)
        try:
            if not _info(handle).dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY:
                raise ValueError('The private data path is not a directory.')
            # Do not change ownership or take over another account's directory.
            owner, dacl, sd = LPVOID(), LPVOID(), LPVOID()
            result = a.a.GetSecurityInfo(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
                                        ctypes.byref(owner), None, None, None, ctypes.byref(sd))
            if result:
                a.fail('Private directory owner query', result)
            try:
                if a.sid_text(owner) != a.sid:
                    raise ValueError('The private directory belongs to another Windows account.')
            finally:
                a.k.LocalFree(sd)
            try:
                _acl(handle, private=True)
                return Path(path)
            except ValueError:
                pass
            # Avoid propagating an unchanged inheritable DACL through the
            # browser cache on every ordinary panel/service launch.
            _protect(handle, directory=True)
            _acl(handle, private=True)
        finally:
            a.k.CloseHandle(handle)
    return Path(path)


def open_private_file(path, flags, mode=0o600):
    del mode  # NTFS ACLs, rather than POSIX mode bits, enforce confidentiality.
    path = _path(path); a = _api()
    access = READ_CONTROL | FILE_READ_ATTRIBUTES
    accmode = flags & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR)
    access |= GENERIC_READ if accmode != os.O_WRONLY else 0
    access |= GENERIC_WRITE if accmode in (os.O_WRONLY, os.O_RDWR) else 0
    disposition = CREATE_NEW if flags & os.O_CREAT and flags & os.O_EXCL else OPEN_ALWAYS if flags & os.O_CREAT else OPEN_EXISTING
    with _parents(path):
        with _security() as (attributes, _descriptor):
            handle = a.k.CreateFileW(_native_path(path), access, FILE_SHARE_READ,
                                     ctypes.byref(attributes), disposition,
                                     FILE_FLAG_OPEN_REPARSE_POINT | FILE_ATTRIBUTE_NORMAL, None)
            if handle == INVALID_HANDLE_VALUE:
                code = ctypes.get_last_error()
                if code in (ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS):
                    raise FileExistsError(code, 'The private file already exists.')
                a.fail('Private file open', code)
        try:
            info = _info(handle)
            if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY or info.nNumberOfLinks != 1:
                raise ValueError('Private application files must be regular files with one hard link.')
            _acl(handle, private=True)
            import msvcrt
            crt_flags = accmode | os.O_BINARY | (flags & os.O_APPEND)
            fd = msvcrt.open_osfhandle(handle, crt_flags)
            handle = None  # The CRT now owns it.
            try:
                if flags & os.O_TRUNC:
                    os.ftruncate(fd, 0)
                return fd
            except BaseException:
                os.close(fd)
                raise
        finally:
            if handle is not None:
                a.k.CloseHandle(handle)


def validate_private_file(path):
    fd = open_private_file(path, os.O_RDONLY)
    os.close(fd)
    return Path(_path(path))


def validate_identity_file(path):
    return validate_private_file(path)


def validate_private_directory(path):
    path = _path(path); a = _api()
    with _parents(path):
        handle = _open_handle(path)
        try:
            if not _info(handle).dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY:
                raise ValueError('The private path is not a directory.')
            _acl(handle, private=True)
        finally:
            a.k.CloseHandle(handle)
    return Path(path)


def read_private_json(path, max_bytes=65536):
    if type(max_bytes) is not int or not 0 < max_bytes <= 1024 * 1024:
        raise ValueError('Invalid private JSON size limit.')
    fd = open_private_file(path, os.O_RDONLY)
    with os.fdopen(fd, 'rb') as stream:
        raw = stream.read(max_bytes + 1)
    if not raw or len(raw) > max_bytes:
        raise ValueError('Invalid private JSON file size.')
    return json.loads(raw.decode('utf-8'))


def atomic_json(path, value):
    return atomic_write(path, json.dumps(value, ensure_ascii=False, indent=2))


def atomic_write(path, text):
    if not isinstance(text, str):
        raise TypeError('Private text writes require a string.')
    path = _path(path)
    validate_private_directory(ntpath.dirname(path))
    if os.path.lexists(path):
        validate_private_file(path)
    temporary = ntpath.join(ntpath.dirname(path), '.' + ntpath.basename(path) + '.' + secrets.token_hex(8) + '.tmp')
    fd = open_private_file(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        # A short, private control-file reader can transiently deny delete share.
        # Bound retries; never replace ACL failures with a permissive fallback.
        deadline = time.monotonic() + .5
        while True:
            try:
                os.replace(temporary, path)
                break
            except PermissionError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(.02)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)


class ServiceLock:
    """An open, unshared Windows file handle excludes another controller."""
    def __init__(self, path):
        self.handle = None
        path = _path(path); a = _api()
        with _parents(path):
            with _security() as (attributes, _descriptor):
                handle = a.k.CreateFileW(_native_path(path), GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
                                         0, ctypes.byref(attributes), OPEN_ALWAYS,
                                         FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, None)
                if handle == INVALID_HANDLE_VALUE:
                    code = ctypes.get_last_error()
                    if code == ERROR_SHARING_VIOLATION:
                        raise RuntimeError('Another service instance is already using this configuration.')
                    a.fail('Service lock open', code)
            try:
                info = _info(handle)
                if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY or info.nNumberOfLinks != 1:
                    raise ValueError('Invalid service lock file.')
                _acl(handle, private=True)
                self.handle = handle
            except BaseException:
                a.k.CloseHandle(handle)
                raise

    def close(self):
        if self.handle is not None:
            _api().k.CloseHandle(self.handle)
            self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()

    def __del__(self):
        with contextlib.suppress(Exception):
            self.close()


def system_executable(name):
    if name not in ('ssh', 'curl'):
        raise ValueError('Only trusted system SSH and curl executables are supported.')
    a = _api(); buffer = ctypes.create_unicode_buffer(32768)
    size = a.k.GetWindowsDirectoryW(buffer, len(buffer))
    if not 0 < size < len(buffer):
        a.fail('Windows directory query')
    folder = ntpath.join(buffer.value, 'System32')
    path = ntpath.join(folder, 'OpenSSH', 'ssh.exe') if name == 'ssh' else ntpath.join(folder, 'curl.exe')
    if not os.path.isfile(path):
        raise OSError('The Windows OpenSSH Client is unavailable. Enable it in Windows Optional Features.' if name == 'ssh'
                      else 'The Windows system curl component is unavailable.')
    return path


def ssh_executable():
    return system_executable('ssh')


def curl_executable():
    return system_executable('curl')


def _environment_block(env):
    values = {}
    for key, value in env.items():
        if not isinstance(key, str) or not key or '=' in key or '\x00' in key or not isinstance(value, str) or '\x00' in value:
            raise ValueError('Invalid Windows child environment.')
        folded = key.casefold()
        if folded in values:
            raise ValueError('Duplicate Windows environment variable names are not allowed.')
        values[folded] = (key, value)
    return '\x00'.join(key + '=' + value for key, value in sorted(values.values(), key=lambda item: item[0].casefold())) + '\x00\x00'


class OwnedProcess:
    def __init__(self, argv, process, job, stdout):
        self.args = list(argv); self.pid = process.dwProcessId
        self.stdout = stdout; self.returncode = None
        self._process = process.hProcess; self._job = job
        self._lock = threading.RLock()
        self._job_lock = threading.RLock()

    def poll(self):
        with self._lock:
            if self.returncode is not None:
                return self.returncode
            a = _api(); result = a.k.WaitForSingleObject(self._process, 0)
            if result == 0x102:
                return None
            if result != 0:
                a.fail('Owned process status query')
            code = DWORD()
            a.check(a.k.GetExitCodeProcess(self._process, ctypes.byref(code)), 'Owned process exit query')
            self.returncode = code.value
            return self.returncode

    def wait(self, timeout=None):
        with self._lock:
            if self.returncode is None:
                milliseconds = 0xFFFFFFFF if timeout is None else min(0xFFFFFFFE, max(0, int(timeout * 1000)))
                result = _api().k.WaitForSingleObject(self._process, milliseconds)
                if result == 0x102:
                    raise subprocess.TimeoutExpired(self.args, timeout)
                if result != 0:
                    _api().fail('Owned process wait')
            return self.poll()

    def terminate_group(self):
        # A thread waiting for the parent must not prevent another thread from
        # terminating its Job. Keep the job-handle lifetime lock independent.
        with self._job_lock:
            if self._job is not None:
                _api().check(_api().k.TerminateJobObject(self._job, 1), 'Owned process termination')

    def kill_group(self):
        self.terminate_group()

    def close(self):
        with self._lock, self._job_lock:
            if self._process is not None and self.poll() is None:
                raise RuntimeError('An active owned process cannot be released.')
            # Closing the job also retires descendants that outlived the parent.
            for name in ('_job', '_process'):
                handle = getattr(self, name, None)
                if handle is not None:
                    _api().k.CloseHandle(handle)
                    setattr(self, name, None)

    def __del__(self):
        # Kernel kill-on-close also applies when the controller itself exits.
        for name in ('_job', '_process'):
            handle = getattr(self, name, None)
            if handle is not None:
                with contextlib.suppress(Exception):
                    _api().k.CloseHandle(handle)
                setattr(self, name, None)


def spawn_owned(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, env=None, close_fds=True):
    """Start suspended, constrain inherited handles, assign a kill-on-close Job, then resume."""
    if stdin != subprocess.DEVNULL or stdout != subprocess.PIPE or stderr != subprocess.STDOUT or not close_fds:
        raise ValueError('Owned components require null stdin and one captured output pipe.')
    if not isinstance(argv, (tuple, list)) or not argv or any(not isinstance(s, str) or '\x00' in s for s in argv):
        raise ValueError('Invalid owned process command.')
    application = _path(argv[0])
    if not os.path.isfile(application):
        raise OSError('The managed Windows component is unavailable.')
    a = _api(); job = None; read_handle = HANDLE(); write_handle = HANDLE(); nul = None
    attribute = None; attribute_initialized = False
    process = PROCESS_INFORMATION(); started = False; reader = None
    try:
        job = a.k.CreateJobObjectW(None, None)
        a.check(job, 'Owned Job creation')
        limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        limits.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        a.check(a.k.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)), 'Owned Job policy')
        pipe_security = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), None, True)
        a.check(a.k.CreatePipe(ctypes.byref(read_handle), ctypes.byref(write_handle), ctypes.byref(pipe_security), 0), 'Owned output pipe creation')
        a.check(a.k.SetHandleInformation(read_handle, 1, 0), 'Owned pipe inheritance')
        nul = a.k.CreateFileW('NUL', GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              ctypes.byref(pipe_security), OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
        if nul == INVALID_HANDLE_VALUE:
            a.fail('Owned null input open')
        needed = SIZE_T()
        a.k.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(needed))
        if not 0 < needed.value < 65536:
            a.fail('Owned handle-list allocation')
        attribute = ctypes.create_string_buffer(needed.value)
        a.check(a.k.InitializeProcThreadAttributeList(attribute, 1, 0, ctypes.byref(needed)), 'Owned handle-list setup')
        attribute_initialized = True
        handle_array = (HANDLE * 2)(nul, write_handle.value)
        a.check(a.k.UpdateProcThreadAttribute(attribute, 0, 0x00020002, handle_array,
                                            ctypes.sizeof(handle_array), None, None), 'Owned handle-list restriction')
        startup = STARTUPINFOEXW()
        startup.StartupInfo.cb = ctypes.sizeof(startup)
        startup.StartupInfo.dwFlags = 0x100  # STARTF_USESTDHANDLES
        startup.StartupInfo.hStdInput = nul
        startup.StartupInfo.hStdOutput = write_handle.value
        startup.StartupInfo.hStdError = write_handle.value
        startup.lpAttributeList = ctypes.cast(attribute, LPVOID)
        command = ctypes.create_unicode_buffer(subprocess.list2cmdline(argv))
        environment = ctypes.create_unicode_buffer(_environment_block(dict(os.environ) if env is None else env))
        flags = 0x00000004 | 0x08000000 | 0x00080000 | 0x00000400
        a.check(a.k.CreateProcessW(application, command, None, None, True, flags,
                                  environment, ntpath.dirname(application), ctypes.byref(startup), ctypes.byref(process)),
                'Owned component start')
        started = True
        a.check(a.k.AssignProcessToJobObject(job, process.hProcess), 'Owned Job assignment')
        if a.k.ResumeThread(process.hThread) == 0xFFFFFFFF:
            a.fail('Owned component resume')
        a.k.CloseHandle(process.hThread); process.hThread = None
        a.k.CloseHandle(write_handle); write_handle = HANDLE()
        a.k.CloseHandle(nul); nul = None
        import msvcrt
        fd = msvcrt.open_osfhandle(read_handle.value, os.O_RDONLY | os.O_BINARY)
        read_handle = HANDLE()
        reader = os.fdopen(fd, 'rb')
        owned = OwnedProcess(argv, process, job, reader)
        process.hProcess = None; job = None; reader = None
        return owned
    except BaseException:
        if started and process.hProcess:
            a.k.TerminateProcess(process.hProcess, 1)
            a.k.WaitForSingleObject(process.hProcess, 2000)
        raise
    finally:
        if attribute_initialized:
            a.k.DeleteProcThreadAttributeList(attribute)
        for handle in (process.hThread, process.hProcess, job, read_handle.value, write_handle.value,
                       None if nul == INVALID_HANDLE_VALUE else nul):
            if handle:
                a.k.CloseHandle(handle)
        if reader is not None:
            reader.close()
