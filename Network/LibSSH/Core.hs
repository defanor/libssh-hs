{- |
Description :  libssh bindings
Maintainer  :  defanor <defanor@uberspace.net>
Stability   :  unstable
Portability :  non-portable

See [the libssh topics](https://api.libssh.org/stable/topics.html) for
a reference.

-}

{-# LANGUAGE CApiFFI #-}

module Network.LibSSH.Core where

import Foreign
import Foreign.C
import Foreign.Storable
import Foreign.Marshal.Utils (with)
import Control.Monad
import Control.Exception


-- * Types

data {-# CTYPE "libssh/libssh.h" "struct ssh_key_struct" #-}
  SSHKeyStruct
type SSHKey = Ptr SSHKeyStruct

data {-# CTYPE "libssh/libssh.h" "struct ssh_session_struct" #-}
  SSHSessionStruct
type SSHSession = Ptr SSHSessionStruct

data {-# CTYPE "libssh/libssh.h" "struct ssh_channel_struct" #-}
  SSHChannelStruct
type SSHChannel = Ptr SSHChannelStruct

data {-# CTYPE "libssh/sftp.h" "struct sftp_session_struct" #-}
  SFTPSessionStruct
type SFTPSession = Ptr SFTPSessionStruct

data {-# CTYPE "libssh/sftp.h" "struct sftp_file_struct" #-}
  SFTPFileStruct
type SFTPFile = Ptr SFTPFileStruct

data {-# CTYPE "libssh/sftp.h" "struct sftp_dir_struct" #-}
  SFTPDirStruct
type SFTPDir = Ptr SFTPDirStruct

data {-# CTYPE "libssh/sftp.h" "struct sftp_attributes_struct" #-}
  SFTPAttributesStruct
type SFTPAttributes = Ptr SFTPAttributesStruct

data {-# CTYPE "libssh/sftp.h" "struct sftp_statvfs_struct" #-}
  SFTPStatvfsStruct
type SFTPStatsvfs = Ptr SFTPStatvfsStruct

type SSHOptionCode = CInt

type SSHAuthCallback = FunPtr
  (CString -> CString -> CSize -> CInt -> CInt -> Ptr CChar -> CInt)

-- ** Option codes

foreign import capi "libssh/libssh.h value SSH_OPTIONS_HOST"
  sshOptionsHost :: SSHOptionCode
foreign import capi "libssh/libssh.h value SSH_OPTIONS_PORT"
  sshOptionsPort :: SSHOptionCode
foreign import capi "libssh/libssh.h value SSH_OPTIONS_PORT_STR"
  sshOptionsPortStr :: SSHOptionCode
foreign import capi "libssh/libssh.h value SSH_OPTIONS_FD"
  sshOptionsFd :: SSHOptionCode
foreign import capi "libssh/libssh.h value SSH_OPTIONS_BINDADDR"
  sshOptionsBindaddr :: SSHOptionCode
foreign import capi "libssh/libssh.h value SSH_OPTIONS_USER"
  sshOptionsUser :: SSHOptionCode
foreign import capi "libssh/libssh.h value SSH_OPTIONS_SSH_DIR"
  sshOptionsSSHDir :: SSHOptionCode
foreign import capi "libssh/libssh.h value SSH_OPTIONS_KNOWNHOSTS"
  sshOptionsKnownhosts :: SSHOptionCode
foreign import capi "libssh/libssh.h value SSH_OPTIONS_GLOBAL_KNOWNHOSTS"
  sshOptionsGlobalKnownhosts :: SSHOptionCode
foreign import capi "libssh/libssh.h value SSH_OPTIONS_IDENTITY"
  sshOptionsIdentity :: SSHOptionCode
foreign import capi "libssh/libssh.h value SSH_OPTIONS_ADD_IDENTITY"
  sshOptionsAddIdentity :: SSHOptionCode
foreign import capi "libssh/libssh.h value SSH_OPTIONS_TIMEOUT"
  sshOptionsTimeout :: SSHOptionCode
foreign import capi "libssh/libssh.h value SSH_OPTIONS_TIMEOUT_USEC"
  sshOptionsTimeoutUsec :: SSHOptionCode

-- * The libssh SFTP API
foreign import capi "libssh/sftp.h sftp_new" sftp_new
  :: SSHSession -> IO SFTPSession
foreign import capi "libssh/sftp.h sftp_new_channel" sftp_new_channel
  :: SSHSession -> SSHChannel -> IO SFTPSession
foreign import capi "libssh/sftp.h sftp_free" sftp_free
  :: SFTPSession -> IO ()
foreign import capi "libssh/sftp.h sftp_init" sftp_init
  :: SFTPSession -> IO CInt
foreign import capi "libssh/sftp.h sftp_get_error" sftp_get_error
  :: SFTPSession -> IO CInt
foreign import capi "libssh/sftp.h sftp_extensions_get_count"
  sftp_extensions_get_count
  :: SFTPSession -> IO CInt
foreign import capi "libssh/sftp.h sftp_extensions_get_name"
  sftp_extensions_get_name
  :: SFTPSession -> CUInt -> IO CString
foreign import capi "libssh/sftp.h sftp_extensions_get_data"
  sftp_extensions_get_data
  :: SFTPSession -> CUInt -> IO CString
foreign import capi "libssh/sftp.h sftp_extension_supported"
  sftp_extension_extension_supported
  :: SFTPSession -> CString -> CString -> IO CInt
foreign import capi "libssh/sftp.h sftp_opendir" sftp_opendir
  :: SFTPSession -> CString -> IO SFTPDir
foreign import capi "libssh/sftp.h sftp_readdir" sftp_readdir
  :: SFTPSession -> SFTPDir -> IO SFTPAttributes
foreign import capi "libssh/sftp.h sftp_dir_eof" sftp_dir_eof
  :: SFTPDir -> IO CInt
foreign import capi "libssh/sftp.h sftp_stat" sftp_stat
  :: SFTPSession -> CString -> IO SFTPAttributes
foreign import capi "libssh/sftp.h sftp_lstat" sftp_lstat
  :: SFTPSession -> CString -> IO SFTPAttributes
foreign import capi "libssh/sftp.h sftp_fstat" sftp_fstat
  :: SFTPFile -> IO SFTPAttributes
foreign import capi "libssh/sftp.h sftp_attributes_free" sftp_attributes_free
  :: SFTPAttributes -> IO ()
foreign import capi "libssh/sftp.h sftp_closedir" sftp_closedir
  :: SFTPDir -> IO CInt
foreign import capi "libssh/sftp.h sftp_close" sftp_close
  :: SFTPFile -> IO CInt
foreign import capi "libssh/sftp.h sftp_open" sftp_open
  :: SFTPSession -> CString -> CInt -> CInt -> IO SFTPFile
foreign import capi "libssh/sftp.h sftp_file_set_nonblocking"
  sftp_file_set_nonblocking
  :: SFTPFile -> IO ()
foreign import capi "libssh/sftp.h sftp_file_set_blocking"
  sftp_file_set_blocking
  :: SFTPFile -> IO ()
foreign import capi "libssh/sftp.h sftp_read" sftp_read
  :: SFTPFile -> CString -> CSize -> IO CInt
foreign import capi "libssh/sftp.h sftp_async_read_begin" sftp_async_read_begin
  :: SFTPFile -> CUInt -> IO CInt
foreign import capi "libssh/sftp.h sftp_async_read" sftp_async_read
  :: SFTPFile -> CString -> CUInt -> CUInt -> IO CInt
foreign import capi "libssh/sftp.h sftp_write" sftp_write
  :: SFTPFile -> CString -> CSize -> IO CInt
foreign import capi "libssh/sftp.h sftp_seek" sftp_seek
  :: SFTPFile -> CUInt -> IO CInt
foreign import capi "libssh/sftp.h sftp_seek64" sftp_seek64
  :: SFTPFile -> CULLong -> IO CInt
foreign import capi "libssh/sftp.h sftp_tell" sftp_tell
  :: SFTPFile -> IO CUInt
foreign import capi "libssh/sftp.h sftp_tell64" sftp_tell64
  :: SFTPFile -> IO CULLong
foreign import capi "libssh/sftp.h sftp_rewind" sftp_rewind
  :: SFTPFile -> IO ()
foreign import capi "libssh/sftp.h sftp_unlink" sftp_unlink
  :: SFTPSession -> CString -> IO CInt
foreign import capi "libssh/sftp.h sftp_rmdir" sftp_rmdir
  :: SFTPSession -> CString -> IO CInt
foreign import capi "libssh/sftp.h sftp_mkdir" sftp_mkdir
  :: SFTPSession -> CString -> CInt -> IO CInt
foreign import capi "libssh/sftp.h sftp_rename" sftp_rename
  :: SFTPSession -> CString -> CString -> IO CInt
foreign import capi "libssh/sftp.h sftp_setstat" sftp_setstat
  :: SFTPSession -> CString -> SFTPAttributes -> IO CInt
foreign import capi "libssh/sftp.h sftp_chown" sftp_chown
  :: SFTPSession -> CString -> CInt -> CInt -> IO CInt
foreign import capi "libssh/sftp.h sftp_chmod" sftp_chmod
  :: SFTPSession -> CString -> CInt -> IO CInt
-- TODO: sftp_utimes
foreign import capi "libssh/sftp.h sftp_symlink" sftp_symlink
  :: SFTPSession -> CString -> CString -> IO CInt
foreign import capi "libssh/sftp.h sftp_readlink" sftp_readlink
  :: SFTPSession -> CString -> IO CString
-- TODO: vfs
foreign import capi "libssh/sftp.h sftp_fsync" sftp_fsync
  :: SFTPFile -> IO CInt
-- TODO: a few more functions

-- * The libssh API
foreign import capi "libssh/libssh.h ssh_init" ssh_init :: IO CInt
foreign import capi "libssh/libssh.h ssh_finalize" ssh_finalize :: IO CInt
-- foreign import capi "libssh/libssh.h libssh_destructor" libssh_destructor :: IO ()

-- ** The SSH authentication functions
foreign import capi "libssh/libssh.h ssh_userauth_try_publickey"
  ssh_userauth_try_publickey
  :: SSHSession -> CString -> SSHKey -> IO CInt
foreign import capi "libssh/libssh.h ssh_userauth_publickey"
  ssh_userauth_publickey
  :: SSHSession -> CString -> SSHKey -> IO CInt
foreign import capi "libssh/libssh.h ssh_userauth_password"
  ssh_userauth_password
  :: SSHSession -> CString -> CString -> IO CInt
foreign import capi "libssh/libssh.h ssh_userauth_agent"
  ssh_userauth_agent
  :: SSHSession -> CString -> IO CInt
foreign import capi "libssh/libssh.h ssh_userauth_none"
  ssh_userauth_none
  :: SSHSession -> CString -> IO CInt

-- ** The SSH channel functions
foreign import capi "libssh/libssh.h ssh_channel_new" ssh_channel_new
  :: SSHSession -> IO SSHChannel
foreign import capi "libssh/libssh.h ssh_channel_open_session"
  ssh_channel_open_session
  :: SSHChannel -> IO CInt
foreign import capi "libssh/libssh.h ssh_channel_free" ssh_channel_free
  :: SSHChannel -> IO ()
foreign import capi "libssh/libssh.h ssh_channel_send_eof" ssh_channel_send_eof
  :: SSHChannel -> IO CInt
foreign import capi "libssh/libssh.h ssh_channel_close" ssh_channel_close
  :: SSHChannel -> IO CInt
foreign import capi "libssh/libssh.h ssh_channel_write" ssh_channel_write
  :: SSHChannel -> CString -> CUInt -> IO CInt
-- foreign import capi "libssh/libssh.h ssh_channel_flush" ssh_channel_flush
--   :: SSHChannel -> IO CInt
foreign import capi "libssh/libssh.h ssh_channel_is_open" ssh_channel_is_open
  :: SSHChannel -> IO CInt
foreign import capi "libssh/libssh.h ssh_channel_is_closed" ssh_channel_is_closed
  :: SSHChannel -> IO CInt
foreign import capi "libssh/libssh.h ssh_channel_is_eof" ssh_channel_is_eof
  :: SSHChannel -> IO CInt
foreign import capi "libssh/libssh.h ssh_channel_set_blocking"
  ssh_channel_set_blocking
  :: SSHChannel -> CInt -> IO ()
foreign import capi "libssh/libssh.h ssh_channel_request_pty"
  ssh_channel_request_pty
  :: SSHChannel -> IO CInt
foreign import capi "libssh/libssh.h ssh_channel_request_shell"
  ssh_channel_request_shell
  :: SSHChannel -> IO CInt
foreign import capi "libssh/libssh.h ssh_channel_request_subsystem"
  ssh_channel_request_subsystem
  :: SSHChannel -> CString -> IO CInt
foreign import capi "libssh/libssh.h ssh_channel_request_sftp"
  ssh_channel_request_sftp
  :: SSHChannel -> IO CInt
foreign import capi "libssh/libssh.h ssh_channel_request_auth_agent"
  ssh_channel_request_auth_agent
  :: SSHChannel -> IO CInt
foreign import capi "libssh/libssh.h ssh_channel_request_exec"
  ssh_channel_request_exec
  :: SSHChannel -> CString -> IO CInt
foreign import capi "libssh/libssh.h ssh_channel_request_send_signal"
  ssh_channel_request_send_signal
  :: SSHChannel -> CString -> IO CInt
foreign import capi "libssh/libssh.h ssh_channel_request_send_break"
  ssh_channel_request_send_break
  :: SSHChannel -> CUInt -> IO CInt
foreign import capi "libssh/libssh.h ssh_channel_read" ssh_channel_read
  :: SSHChannel -> CString -> CUInt -> CInt -> IO CInt
foreign import capi "libssh/libssh.h ssh_channel_read_timeout"
  ssh_channel_read_timeout
  :: SSHChannel -> CString -> CUInt -> CInt -> CInt -> IO CInt
foreign import capi "libssh/libssh.h ssh_channel_read_nonblocking"
  ssh_channel_read_nonblocking
  :: SSHChannel -> CString -> CUInt -> CInt -> IO CInt
foreign import capi "libssh/libssh.h ssh_channel_poll" ssh_channel_poll
  :: SSHChannel -> CInt -> IO CInt
foreign import capi "libssh/libssh.h ssh_channel_poll_timeout"
  ssh_channel_poll_timeout
  :: SSHChannel -> CInt -> CInt -> IO CInt
foreign import capi "libssh/libssh.h ssh_channel_get_session"
  ssh_channel_get_session
  :: SSHChannel -> IO SSHSession
foreign import capi "libssh/libssh.h ssh_channel_get_exit_status"
  ssh_channel_get_exit_status
  :: SSHChannel -> IO CInt

-- ** The SSH error functions
foreign import capi "libssh/libssh.h ssh_get_error" ssh_get_error
  :: Ptr () -> IO CString
foreign import capi "libssh/libssh.h ssh_get_error_code" ssh_get_error_code
  :: Ptr () -> IO CInt

-- ** The SSH logging functions
foreign import capi "libssh/sftp.h ssh_set_log_level" ssh_set_log_level
  :: CInt -> IO CInt
foreign import capi "libssh/sftp.h ssh_get_log_level" ssh_get_log_level
  :: IO CInt

-- ** The SSH helper functions
foreign import capi "libssh/sftp.h ssh_version" ssh_version
  :: CInt -> IO CString

-- ** The SSH Public Key Infrastructure
foreign import capi "libssh/libssh.h ssh_pki_import_pubkey_file"
  ssh_pki_import_pubkey_file
  :: CString -> Ptr SSHKey -> IO CInt
foreign import capi "libssh/libssh.h ssh_pki_import_privkey_file"
  ssh_pki_import_privkey_file
  :: CString -> CString -> SSHAuthCallback -> Ptr () -> Ptr SSHKey -> IO CInt
foreign import capi "libssh/libssh.h ssh_key_free"
  ssh_key_free
  :: SSHKey -> IO ()

-- ** The SSH session functions
foreign import capi "libssh/libssh.h ssh_service_request" ssh_service_request
  :: SSHSession -> CString -> IO CInt
foreign import capi "libssh/libssh.h ssh_connect" ssh_connect
  :: SSHSession -> IO CInt
foreign import capi "libssh/libssh.h ssh_get_issue_banner" ssh_get_issue_banner
  :: SSHSession -> IO CString
foreign import capi "libssh/libssh.h ssh_get_openssh_version"
  ssh_get_openssh_version
  :: SSHSession -> IO CInt
foreign import capi "libssh/libssh.h ssh_session_set_disconnect_message"
  ssh_session_set_disconnect_message
  :: SSHSession -> CString -> IO CInt
foreign import capi "libssh/libssh.h ssh_copyright" ssh_copyright
  :: IO CString
foreign import capi "libssh/libssh.h ssh_disconnect" ssh_disconnect
  :: SSHSession -> IO ()
foreign import capi "libssh/libssh.h ssh_options_copy" ssh_options_copy
  :: SSHSession -> Ptr SSHSession -> IO CInt
foreign import capi "libssh/libssh.h ssh_options_set" ssh_options_set
  :: SSHSession -> SSHOptionCode -> Ptr () -> IO CInt
foreign import capi "libssh/libssh.h ssh_options_parse_config"
  ssh_options_parse_config
  :: SSHSession -> CString -> IO CInt
-- foreign import capi "libssh/libssh.h ssh_options_apply" ssh_options_apply
--   :: SSHSession -> IO CInt
foreign import capi "libssh/libssh.h ssh_new" ssh_new :: IO SSHSession
foreign import capi "libssh/libssh.h ssh_free" ssh_free
  :: SSHSession -> IO ()
foreign import capi "libssh/libssh.h ssh_silent_disconnect"
  ssh_silent_disconnect
  :: SSHSession -> IO ()
foreign import capi "libssh/libssh.h ssh_set_blocking" ssh_set_blocking
  :: SSHSession -> CInt -> IO ()
foreign import capi "libssh/libssh.h ssh_is_blocking" ssh_is_blocking
  :: SSHSession -> IO CInt
foreign import capi "libssh/libssh.h ssh_blocking_flush" ssh_blocking_flush
  :: SSHSession -> CInt -> IO CInt
foreign import capi "libssh/libssh.h ssh_is_connected" ssh_is_connected
  :: SSHSession -> IO CInt
foreign import capi "libssh/libssh.h ssh_get_status" ssh_get_status
  :: SSHSession -> IO CInt
foreign import capi "libssh/libssh.h ssh_get_poll_flags" ssh_get_poll_flags
  :: SSHSession -> IO CInt
foreign import capi "libssh/libssh.h ssh_get_disconnect_message"
  ssh_get_disconnect_message
  :: SSHSession -> IO CString
foreign import capi "libssh/libssh.h ssh_get_version" ssh_get_version
  :: SSHSession -> IO CInt
foreign import capi "libssh/libssh.h ssh_send_ignore" ssh_send_ignore
  :: SSHSession -> CString -> IO CInt
foreign import capi "libssh/libssh.h ssh_send_debug" ssh_send_debug
  :: SSHSession -> CString -> CInt -> IO CInt
