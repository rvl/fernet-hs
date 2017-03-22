-- | /Fernet/ generates and verifies HMAC-based authentication tokens.
--
-- Originally designed for use within OpenStack clusters, it was
-- intended to be fast and light-weight, with non-persistent
-- tokens. Integrity and confidentiality of the token contents are
-- implemented with HMAC SHA256 and AES128 CBC.
--
-- See the <https://github.com/fernet/spec/blob/master/Spec.md Fernet Spec>
-- for a little more information.
--
-- == Usage
-- To encrypt a token:
--
-- >>> import Network.Fernet
-- >>> k <- generateKey
-- >>> keyToBase64 k
-- "JQAeL3iFN9wIW_hMKiIzA1EiG_EZNivnMPBOOJn2wZc="
-- >>> token <- encrypt k "secret text"
-- >>> print token
-- "gAAAAABY0H9kx7ihkcj6ZF_bQ73Lvc7aG-ZlEtjx24io-DQy5tCjLbq1JvVY27uAe6BuwG8css-4LDIywOJRyY_zetq7aLPPag=="
--
-- The resulting token can be distributed to clients. To check and
-- decrypt the token, use the same key:
--
-- >>> decrypt k 60 token
-- Right "secret text"
--
-- When decrypting, a TTL value is supplied to determine whether the
-- token has expired. The timestamp is stored in plain text and can
-- also be checked with 'hasExpired'.
--
-- == Related Modules
--
-- * "Network.Iron"
-- * "Jose.Jwt"

module Network.Fernet
  ( -- * Tokens
    encrypt
  , decrypt
  , encrypt'
  , decrypt'
  , DecryptError(..)
  , isExpired
  , hasExpired
  -- * Keys
  , Key
  , key
  , generateKey
  , generateKeyFromPassword
  , keyFromBase64
  , keyToBase64
  -- * Other
  , version
  ) where

import           Data.ByteString        (ByteString)
import qualified Data.ByteString        as BS
import           Data.ByteArray         (ScrubbedBytes)
import           Data.Byteable          (constEqBytes)
import           Data.Word              (Word8)
import           Data.Time.Clock        (NominalDiffTime)
import           Data.Time.Clock.POSIX  (POSIXTime, getPOSIXTime)
import           Data.Bifunctor         (first)

import Network.Fernet.Crypto
import Network.Fernet.Key
import Network.Fernet.Token

-- | @0x80@ is the latest token format version, and the only one
-- supported by this library.
version :: Word8
version = 0x80

----------------------------------------------------------------------------
-- Encryption

-- | Encrypts, encodes, and signs the given token contents with the
-- given key.
--
-- Its timestamp is set to the current time and stored /unencrypted/
-- in the token.
encrypt :: Key -- ^ The encryption and signing keys.
        -> ByteString -- ^ Token contents.
        -> IO ByteString -- ^ An encoded /Fernet/ token.
encrypt k text = do
  ts <- getPOSIXTime
  iv <- genIV
  return $ encrypt' k ts iv text

-- | Encrypts, encodes, and signs the given token contents with the
-- given key.
--
-- The provided timestamp is stored /unencrypted/ in the token.
--
-- The given IV (initialization vector) string should be a random
-- sequence of exactly 128 bits.
encrypt' :: Key          -- ^ The encryption and signing keys.
         -> POSIXTime    -- ^ Timestamp
         -> ByteString   -- ^ Initialization Vector.
         -> ByteString   -- ^ Token contents.
         -> ByteString   -- ^ An encoded /Fernet/ token.
encrypt' Key{..} ts iv text =
  case serialize <$> makeToken encryptionKey ts iv text of
    Just token -> encode token (sign signingKey token)
    Nothing -> "" -- this shouldn't happen, unless iv is wrong

makeToken :: ScrubbedBytes     -- ^ Keys
          -> POSIXTime         -- ^ Timestamp
          -> ByteString        -- ^ Initialization Vector
          -> ByteString        -- ^ Plain text
          -> Maybe TokenFields
makeToken k ts iv text = TokenFields version ts iv <$> ct
  where ct = aesEncrypt k iv text

----------------------------------------------------------------------------
-- Decryption

-- | Some of the reasons why decryption can fail.
data DecryptError = TokenMalformed     -- ^ The token could not be decoded into fields.
                  | TokenInvalid       -- ^ Signature verification failed.
                  | TokenExpired       -- ^ Token age exceeded given TTL value.
                  | UnacceptableClockSkew -- ^ Token timestamp is too far in the future.
                  | KeySizeInvalid     -- ^ The key was not suitable for decryption.
                  | InvalidBlockSize   -- ^ The ciphertext length was not a multiple of the block size.
                  | UnsupportedVersion -- ^ The version was not 0x80.
                  deriving (Show, Eq)

-- | Decodes, checks, and decrypts, the given /Fernet/ token.
--
-- If the token's age (determined by its timestamp) exceeds the given
-- TTL, then this function will fail.
decrypt :: Key             -- ^ The encryption and signing keys.
        -> NominalDiffTime -- ^ Token TTL.
        -> ByteString      -- ^ The encoded token.
        -> IO (Either DecryptError ByteString) -- ^ Token contents, or an error.
decrypt k ttl t = do
  now <- getPOSIXTime
  return $ decrypt' k ttl now t

-- | Decodes, checks, and decrypts, the given /Fernet/ token.
--
-- If the token's age (determined by its timestamp) exceeds the given
-- TTL, then this function will fail.
decrypt' :: Key             -- ^ The encryption and signing keys.
         -> NominalDiffTime -- ^ Token TTL.
         -> POSIXTime       -- ^ The current time, used to determine token age.
         -> ByteString      -- ^ The encoded token.
         -> Either DecryptError ByteString -- ^ Token contents, or an error.
decrypt' Key{..} ttl now t = do
  (fields, tb, sig) <- first (const TokenMalformed) (decode t)
  checkVersion fields
  checkTimestamp now fields
  checkExpiry ttl now fields
  checkSignature signingKey tb sig
  checkInputSize fields
  case aesDecrypt encryptionKey (tokenIV fields) (tokenCiphertext fields) of
    Just text -> Right text
    Nothing -> Left KeySizeInvalid

checkVersion :: TokenFields -> Either DecryptError ()
checkVersion tf | tokenVersion tf == version = Right ()
                | otherwise = Left UnsupportedVersion

-- | Maximum clock skew in the future direction.
maxClockSkew :: NominalDiffTime
maxClockSkew = 60

checkTimestamp :: POSIXTime -> TokenFields -> Either DecryptError ()
checkTimestamp now TokenFields{..} | tokenTimestamp - now <= maxClockSkew = Right ()
                                   | otherwise = Left UnacceptableClockSkew

checkExpiry :: NominalDiffTime -> POSIXTime -> TokenFields -> Either DecryptError ()
checkExpiry ttl now tf | hasExpired' ttl now tf = Right ()
                       | otherwise = Left TokenExpired

checkSignature :: ScrubbedBytes -> ByteString -> ByteString -> Either DecryptError ()
checkSignature k tf sig | constEqBytes sig (sign k tf) = Right ()
                        | otherwise                    = Left TokenInvalid

checkInputSize :: TokenFields -> Either DecryptError ()
checkInputSize tf | isBlocked (tokenCiphertext tf) = Right ()
                  | otherwise                      = Left InvalidBlockSize
  where isBlocked t = BS.length t `mod` cipherBlockSize == 0
