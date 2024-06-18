{- |
Description :  libssh bindings
Maintainer  :  defanor <defanor@uberspace.net>
Stability   :  unstable
Portability :  non-portable

See [the libssh documentation](https://api.libssh.org/stable/) for its
API reference and a usage tutorial.

These bindings are intended to be simple, predictable, and stay close
to the original library, only providing a Haskell API with more
conventional types, replacing error codes with exceptions, helping to
ensure that allocated resources are freed (using the "with"
functions). All the used types and utility functions are exposed.

A usage example:

@
import Network.LibSSH as SSH
import qualified Data.ByteString.Char8 as BS

main :: IO ()
main = 'withSSH' $
  'withSession' [OptHost "example.com", OptPort 22, OptUser (Just "user"),
               OptKnownhosts Nothing, OptTimeout 600] $ \\session ->
  'withConnection' session $ do
  'authenticateWithKeys' session Nothing "id_rsa.pub" "id_rsa" Nothing
  'withSessionChannel' session $ \\channel ->
    'channelRequestExec' channel "uname -a"
    >> 'channelReadAll' channel >>= BS.putStrLn
  'withSFTPSession' session $ \\sftp -> do
    'sftpRead' sftp "\/tmp\/example.txt" >>= BS.putStrLn
    'sftpUnlink' sftp "\/tmp\/example.txt"
@

-}

module Network.LibSSH where

import Network.LibSSH.Core
import qualified Data.ByteString.Char8 as BS
import Control.Exception
import Foreign
import Foreign.C
import Foreign.Ptr


-- | Invokes 'ssh_init' and 'ssh_finalize'. Library usage must be
-- wrapped into it for correct functioning if libssh is linked
-- statically, or with its versions before 0.8.0. Not necessary, but
-- still safe to use otherwise.
withSSH :: IO a -> IO a
withSSH a = ssh_init >> a `finally` ssh_finalize


-- * Public Key Infrastructure

-- | Imports a public key from a file or a PKCS #11 device, performs
-- an action with it.
withPublicKeyFile :: FilePath -> (SSHKey -> IO a) -> IO a
withPublicKeyFile path f =
  withCString path $ \pubKeyPath ->
  alloca $ \pubKeyPtr -> do
  throwOnError "ssh_pki_import_pubkey_file"
    (ssh_pki_import_pubkey_file pubKeyPath pubKeyPtr)
  pubKey <- peek pubKeyPtr
  f pubKey `finally` ssh_key_free pubKey

-- | Imports a private key from a file or a PKCS #11 device, performs
-- an action with it.
withPrivateKeyFile :: FilePath -> Maybe String -> (SSHKey -> IO a) -> IO a
withPrivateKeyFile privKeyPath passphrase f =
  withCString privKeyPath $ \privKeyPathCStr ->
  withCStringMaybe passphrase $ \passphraseCStr ->
  alloca $ \privKeyPtr -> do
  -- Skipping a callback to ssh_pki_import_privkey_file here, though
  -- it may be nice to implement in the future.
  throwOnError "ssh_pki_import_privkey_file"
    (ssh_pki_import_privkey_file
     privKeyPathCStr passphraseCStr nullFunPtr nullPtr privKeyPtr)
  privKey <- peek privKeyPtr
  f privKey `finally` ssh_key_free privKey


-- * Session

data SSHOption = OptHost String
               | OptPort Int
               | OptPortStr String
               | OptFd Int
               | OptBindaddr String
               | OptUser (Maybe String)
               | OptSSHDir (Maybe FilePath)
               | OptKnownhosts (Maybe FilePath)
               --  | OptGlobalKnownhosts (Maybe FilePath)
               | OptIdentity String
               | OptTimeout Int
               | OptTimeoutUsec Int

setOption :: SSHSession -> SSHOption -> IO ()
setOption session option =
  let so opt val = throwOnError "ssh_options_set"
                   (ssh_options_set session opt (castPtr val))
                   >> pure ()
  in case option of
    OptHost host -> withCString host (so sshOptionsHost)
    OptPort port -> with (fromIntegral port :: CInt) (so sshOptionsPort)
    OptPortStr host -> withCString host (so sshOptionsPortStr)
    OptFd fd -> with (fromIntegral fd :: CInt) (so sshOptionsFd)
    OptBindaddr addr -> withCString addr (so sshOptionsBindaddr)
    OptUser user -> withCStringMaybe user (so sshOptionsUser)
    OptSSHDir dir -> withCStringMaybe dir (so sshOptionsSSHDir)
    OptKnownhosts hf -> withCStringMaybe hf (so sshOptionsKnownhosts)
    -- OptGlobalKnownhosts ghf -> withCStringMaybe ghf (so sshOptionsGlobalKnownhosts)
    OptIdentity idfn -> withCString idfn (so sshOptionsIdentity)
    OptTimeout sec -> with (fromIntegral sec :: CInt) (so sshOptionsTimeout)
    OptTimeoutUsec usec -> with (fromIntegral usec :: CInt) (so sshOptionsTimeoutUsec)

-- | Performs an action with a new session, with options set for it.
withSession :: [SSHOption] -> (SSHSession -> IO a) -> IO a
withSession options action =
  bracket (throwOnNull "ssh_new" ssh_new) ssh_free $ \session ->
  mapM_ (setOption session) options >> action session

-- | Connects, performs an action, disconnects.
withConnection :: SSHSession -> IO a -> IO a
withConnection session action =
  throwOnError "ssh_options_setssh_connect" (ssh_connect session)
  >> (action `finally` (ssh_disconnect session))


-- ** Authentication

-- | Authenticates using the provided key pair.
authenticateWithKeys :: SSHSession
                     -> Maybe String
                     -- ^ Username, SHOULD be 'Nothing'.
                     -> FilePath
                     -- ^ Public key file
                     -> FilePath
                     -- ^ Private key file
                     -> Maybe String
                     -- ^ Passphrase
                     -> IO ()
authenticateWithKeys session username pubKeyFile privKeyFile passphrase =
  withCStringMaybe username $ \usernameCStr ->
  withPublicKeyFile pubKeyFile
  (\pubKey -> throwOnError "ssh_userauth_try_publickey"
    (ssh_userauth_try_publickey session usernameCStr pubKey))
  >> (withPrivateKeyFile privKeyFile passphrase
      (\privKey -> throwOnError "ssh_userauth_publickey"
        (ssh_userauth_publickey session usernameCStr privKey)))
  >> pure ()

-- | Authenticates using a password
authenticateWithPassword :: SSHSession
                         -> Maybe String
                         -- ^ Username, SHOULD be 'Nothing'.
                         -> String
                         -- ^ Password
                         -> IO ()
authenticateWithPassword session username password =
  withCStringMaybe username $ \usernameCStr ->
  withCString password
  (\passwordCStr ->
     throwOnError "ssh_userauth_password"
    (ssh_userauth_password session usernameCStr passwordCStr))
  >> pure ()

-- | Authenticates using SSH agent.
authenticateWithAgent :: SSHSession
                      -> Maybe String
                      -- ^ Username, SHOULD be 'Nothing'.
                      -> IO ()
authenticateWithAgent session username =
  withCStringMaybe username $ \usernameCStr ->
  (throwOnError "ssh_userauth_agent"
    (ssh_userauth_agent session usernameCStr))
  >> pure ()

-- | Authenticates using the "none" method.
authenticateWithNone :: SSHSession
                     -> Maybe String
                     -- ^ Username, SHOULD be 'Nothing'.
                     -> IO ()
authenticateWithNone session username =
  withCStringMaybe username $ \usernameCStr ->
  (throwOnError "ssh_userauth_none"
    (ssh_userauth_none session usernameCStr))
  >> pure ()

-- * Channels

-- | Performs an action with a new channel ('ssh_channel_new').
withChannel :: SSHSession -> (SSHChannel -> IO a) -> IO a
withChannel session =
  bracket (throwOnNull "ssh_channel_new" $ ssh_channel_new session)
  ssh_channel_free

-- | Performs an action with a new session channel
-- ('ssh_channel_open_session').
withSessionChannel :: SSHSession -> (SSHChannel -> IO a) -> IO a
withSessionChannel session f = withChannel session $ \channel -> do
  throwOnError "ssh_channel_open_session" $ ssh_channel_open_session channel
  f channel `finally` ssh_channel_close channel

-- | Executes a shell command with 'ssh_channel_request_exec'.
channelRequestExec :: SSHChannel -> String -> IO CInt
channelRequestExec channel cmd = do
  withCString cmd $ \cmdCStr ->
    throwOnError "ssh_channel_request_exec"
    (ssh_channel_request_exec channel cmdCStr)

-- | Reads all data from a channel with 'ssh_channel_read' and
-- 'readAll'.
channelReadAll :: SSHChannel -> IO BS.ByteString
channelReadAll channel =
  readAll "ssh_channel_read" (\buf len -> ssh_channel_read channel buf len 0)


-- * SFTP

-- | Performs an action with a new SFTP session.
withSFTPSession :: SSHSession -> (SFTPSession -> IO a) -> IO a
withSFTPSession session f =
  bracket (throwOnNull "sftp_new" $ sftp_new session) sftp_free $ \sftp -> do
  throwOnError "sftp_init" $ sftp_init sftp
  f sftp

-- | Reads file contents over SFTP.
sftpRead :: SFTPSession -> FilePath -> IO BS.ByteString
sftpRead sftp path = withCString path $ \pathCStr ->
  bracket (throwOnNull "sftp_open" $ sftp_open sftp pathCStr 0 0) sftp_close $
  \file -> readAll "sftp_read" (sftp_read file)

-- | Unlinks (deletes, removes) a remote file.
sftpUnlink :: SFTPSession -> FilePath -> IO ()
sftpUnlink session path = withCString path $ \pathCStr ->
  throwOnError "sftp_unlink" (sftp_unlink session pathCStr) >> pure ()


-- * Utility functions and exceptions

data SSHErrorType = SSHErrorCode Int | SSHNull
  deriving (Show)

data SSHError = SSHError String SSHErrorType
  deriving (Show)

instance Exception SSHError

-- | Throws an exception if the number returned by the provided action
-- is less than 0.
throwOnError :: Integral a
             => String
             -- ^ Function name
             -> IO a
             -- ^ Action to run
             -> IO a
throwOnError fname action = do
  result <- action
  if fromIntegral result < 0
    then throw (SSHError fname (SSHErrorCode $ fromIntegral result))
    else pure result

-- | Throws an exception if the performed action returns a NULL.
throwOnNull :: String
            -- ^ Function name
            -> IO (Ptr a)
            -- ^ Action to run
            -> IO (Ptr a)
throwOnNull fname action = do
  result <- action
  if result == nullPtr
    then throw (SSHError fname SSHNull)
    else pure result

-- | Reads data using a provided action, until the returned number is
-- 0 (indicating EOF) or less (indicating an error, leading to an
-- exception).
readAll :: (Integral a, Integral b)
        => String
        -- ^ Function name
        -> (CString -> a -> IO b)
        -- ^ A reader action, such as 'ssh_channel_read' or 'sftp_read'
        -> IO BS.ByteString
readAll fname f =
  let readChunks = allocaBytes 4096 $ \buf -> do
        chunkLen <- throwOnError fname $ f buf (fromIntegral 4096)
        if chunkLen == 0
          then pure []
          else (:)
               <$> BS.packCStringLen (buf, fromIntegral chunkLen)
               <*> readChunks
  in BS.concat <$> readChunks

-- | Like 'withCString', but provides a 'nullPtr' on 'Nothing'.
withCStringMaybe :: Maybe String -> (CString -> IO a) -> IO a
withCStringMaybe Nothing a = a nullPtr
withCStringMaybe (Just s) a = withCString s a
