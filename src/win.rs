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
        const READ              = 0x00000001;
        const WRITE             = 0x00000002;
        const APPEND            = 0x00000004;
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

    pub struct ExtFileAttr: u32 {
        const READONLY          = 0x00000001;
        const HIDDEN            = 0x00000002;
        const SYSTEM            = 0x00000004;
        const DIRECTORY         = 0x00000010;
        const ARCHIVE           = 0x00000020;
        const NORMAL            = 0x00000080;
        const TEMP              = 0x00000100;
        const COMPRESSED        = 0x00000800;
        const POSIX             = 0x01000000;
        const BACKUP            = 0x02000000;
        const DELETE_ON_CLOSE   = 0x04000000;
        const SQUENTIAL_ACCESS  = 0x08000000;
        const RANDOM_ACCESS     = 0x10000000;
        const NO_BUFFERING      = 0x20000000;
        const WRITE_THROUGH     = 0x80000000;
    }

    pub struct TreeConnectFlags: u16 {
        const DISCONNECT_TID        = 0x0001;
        const EXTENDED_SIGNATURE    = 0x0004;
        const EXTENDED_RESPONSE     = 0x0008;
    }

    pub struct ShareAccess: u32 {
        const NONE              = 0x00000000;
        const READ              = 0x00000001;
        const WRITE             = 0x00000002;
        const DELETE            = 0x00000004;
    }

    pub struct CreateFlags: u32 {
        const REQUEST_OPLOCK    = 0x00000002;
        const REQUEST_OPBATCH   = 0x00000004;
        const OPEN_TARGET_DIR   = 0x00000008;
    }

    pub struct CreateDisposition: u32 {
        const SUPERSEDE         = 0x00000000;
        const OPEN              = 0x00000001;
        const CREATE            = 0x00000002;
        const OPEN_IF           = Self::OPEN.bits | Self::CREATE.bits;
        const OVERWRITE         = 0x00000004;
        const OVERWRITE_IF      = Self::OPEN.bits | Self::OVERWRITE.bits;
    }

    pub struct CreateOptions: u32 {
        const DIRECTORY         = 0x00000001;
        const WRITE_THROUGH     = 0x00000002;
        const SEQUENTIAL_ONLY   = 0x00000004;
        const NO_BUFFERING      = 0x00000008;
        const NON_DIRECTORY     = 0x00000040;
        const NO_EA_KNOWLEDGE   = 0x00000200;
        const RANDOM_ACCESS     = 0x00000800;
        const DELETE_ON_CLOSE   = 0x00001000;
        const OPEN_BY_FID       = 0x00002000;
        const INTENT_BACKUP     = 0x00004000;
        const NO_COMPRESSION    = 0x00008000;
        const NO_RECALL         = 0x00400000;
    }

    pub struct ImpersonationLevel: u32 {
        const ANONYMOUS         = 0x00000000;
        const IDENTIFY          = 0x00000001;
        const IMPERSONATE       = 0x00000002;
    }

    pub struct SecurityFlags: u8 {
        const CONTEXT_TRACKING  = 0x01;
        const EFFECTIVE_ONLY    = 0x02;
    }

    pub struct SmbFileAttr: u16 {
        const NORMAL            = 0x0000;
        const READONLY          = 0x0001;
        const HIDDEN            = 0x0002;
        const SYSTEM            = 0x0004;
        const VOLUME            = 0x0008;
        const DIRECTORY         = 0x0010;
        const ARCHIVE           = 0x0020;
        const SEARCH_READONLY   = 0x0100;
        const SEARCH_HIDDEN     = 0x0200;
        const SEARCH_SYSTEM     = 0x0400;
        const SEARCH_DIRECTORY  = 0x1000;
        const SEARCH_ARCHIVE    = 0x2000;
    }

    pub struct OpLockLevel: u8 {
        const NO_LOCK           = 0x00;
        const EXCLUSIVE         = 0x01;
        const BATCH             = 0x02;
        const LEVEL2            = Self::EXCLUSIVE.bits | Self::BATCH.bits;
    }

    pub struct ResourceType: u16 {
        const DISK              = 0x0000;
        const BYTE_PIPE         = 0x0001;
        const MESSAGE_PIPE      = 0x0002;
        const PRINTER           = Self::BYTE_PIPE.bits | Self::MESSAGE_PIPE.bits;
        const COMM_DEVICE       = 0x0004;
    }
}
