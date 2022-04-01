use bitflags::bitflags;
use num_enum::{IntoPrimitive, TryFromPrimitive};

/// NTStatus is the status code reported in a SMB header.
/// This would ideally be a C-enum of the following list:
/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
/// But since i'm not that crazy i define only the values from the SMB specification
/// and treat the rest as "unknown".
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoPrimitive, TryFromPrimitive)]
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum NTStatus {
    SUCCESS                 = 0x00000000,
    INVALID_SMB             = 0x00010002,
    BAD_TID                 = 0x00050002,
    BAD_COMMAND             = 0x00160002,
    BAD_UID                 = 0x005b0002,
    NON_STANDARD            = 0x00fb0002,
    BUFFER_OVERFLOW         = 0x80000005,
    NO_MORE_FILES           = 0x80000006,
    STOPPED_ON_SYMLINK      = 0x8000002d,
    NOT_IMPLEMENTED         = 0xc0000002,
    INVALID_PARAMETER       = 0xc000000d,
    NO_SUCH_DEVICE          = 0xc000000e,
    INVALID_DEVICE_REQ      = 0xc0000010,
    MORE_PROCESSING         = 0xc0000016,
    ACCESS_DENIED           = 0xc0000022,
    BUFFER_TOO_SMALL        = 0xc0000023,
    NAME_NOT_FOUND          = 0xc0000034,
    NAME_COLLISION          = 0xc0000035,
    PATH_NOT_FOUND          = 0xc000003a,
    LOGIN_FAILURE           = 0xc000006d,
    BAD_IMPERSONATION       = 0xc00000a5,
    IO_TIMEOUT              = 0xc00000b5,
    FILE_IS_DIRECTORY       = 0xc00000ba,
    NOT_SUPPORTED           = 0xc00000bb,
    NETWORK_NAME_DELETED    = 0xc00000c9,
    USER_SESSION_DELETED    = 0xc0000203,
    NETWORK_SESSION_EXPIRED = 0xc000035c,
    TOO_MANY_UIDS           = 0xc000205a,
}


bitflags! {
    /// File Acces Mask
    pub struct FileAccessMask: u32 {
        const READ_DATA         = 0x00000001;
        const WRITE_DATA        = 0x00000002;
        const APPEND_DATA       = 0x00000004;
        const READ_EA           = 0x00000008;
        const WRITE_EA          = 0x00000010;
        const EXECUTE           = 0x00000020;
        const DELETE_CHILD      = 0x00000040;
        const READ_ATTRIBUTES   = 0x00000080;
        const WRITE_ATTRIBUTES  = 0x00000100;
        const DELETE            = 0x00010000;
        const READ_CONTROL      = 0x00020000;
        const WRITE_DAC         = 0x00040000;
        const WRITE_OWNER       = 0x00080000;
        const SYNCHRONIZE       = 0x00100000;
        const ACCESS_SECURITY   = 0x01000000;
        const MAXIMUM_ALLOWED   = 0x02000000;
        const GENERIC_ALL       = 0x10000000;
        const GENERIC_EXECUTE   = 0x20000000;
        const GENERIC_WRITE     = 0x40000000;
        const GENERIC_READ      = 0x80000000;
    }

    /// Directory Acces Mask
    pub struct DirAccessMask: u32 {
        const LIST_DIRECTORY    = 0x00000001;
        const ADD_FILE          = 0x00000002;
        const ADD_SUBDIRECTORY  = 0x00000004;
        const READ_EA           = 0x00000008;
        const WRITE_EA          = 0x00000010;
        const TRAVERSE          = 0x00000020;
        const DELETE_CHILD      = 0x00000040;
        const READ_ATTRIBUTES   = 0x00000080;
        const WRITE_ATTRIBUTES  = 0x00000100;
        const DELETE            = 0x00010000;
        const READ_CONTROL      = 0x00020000;
        const WRITE_DAC         = 0x00040000;
        const WRITE_OWNER       = 0x00080000;
        const SYNCHRONIZE       = 0x00100000;
        const ACCESS_SECURITY   = 0x01000000;
        const MAXIMUM_ALLOWED   = 0x02000000;
        const GENERIC_ALL       = 0x10000000;
        const GENERIC_EXECUTE   = 0x20000000;
        const GENERIC_WRITE     = 0x40000000;
        const GENERIC_READ      = 0x80000000;
    }
}
