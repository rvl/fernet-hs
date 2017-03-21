module Network.Fernet.Key
  ( Key(..)
  , key
  , generateKey
  , generateKeyFromPassword
  , keyFromBase64
  , keyToBase64
  ) where

import           Data.Monoid            ((<>))
import           Data.ByteString        (ByteString)
import qualified Data.ByteString        as BS
import           Data.Byteable          (Byteable(..))
import           Data.ByteArray         (ScrubbedBytes, ByteArrayAccess(..))
import qualified Data.ByteArray         as BA
import qualified Crypto.KDF.PBKDF2      as PBKDF2
import           Crypto.Hash.Algorithms (SHA256(..))
import           Crypto.Random          (getRandomBytes)

import Network.Fernet.Base64

-- | Contains the signing key and encryption key. Create one with
-- 'key', 'keyFromBase64', or 'generateKeyFromPassword'.
data Key = Key
           { signingKey    :: ScrubbedBytes
           , encryptionKey :: ScrubbedBytes
           } deriving (Show, Eq)

-- | Constructs a pair of signing and encryption keys. Each key must
-- be exactly 16 bytes long or this will fail.
key :: ByteArrayAccess a
    => a   -- ^ Signing Key
    -> a   -- ^ Encryption Key
    -> Maybe Key
key s e = Key <$> toKey checkHashKeyLength s <*> toKey checkCipherKeyLength e

toKey :: ByteArrayAccess a => (Int -> Bool) -> a -> Maybe ScrubbedBytes
toKey checkLength k | checkLength (BA.length k) = Just (BA.convert k)
                    | otherwise                      = Nothing

cipherKeyLength :: Int
cipherKeyLength = 16

-- | Check that key length is appropriate for AES128.
checkCipherKeyLength :: Int -> Bool
checkCipherKeyLength = (== cipherKeyLength)

checkHashKeyLength :: Int -> Bool
checkHashKeyLength = (>= 16)

-- | Generates new keys from the PRNG.
generateKey :: IO Key
generateKey = splitKeys <$> getRandomBytes (cipherKeyLength * 2)

-- | Input must be exactly length 32 chars
splitKeys :: ByteString -> Key
splitKeys = make . BS.splitAt cipherKeyLength
  where make (s, e) = Key (BA.convert s) (BA.convert e)

genSalt :: IO ByteString
genSalt = getRandomBytes 16

-- | Encodes the given key as urlsafe base64.
keyToBase64 :: Key -> ByteString -- ^ URL-safe base64.
keyToBase64 (Key s e) = b64url $ s <> e

-- | Decodes urlsafe base64-encoded bytes into a key. This will fail
-- if the input is not exactly 256 bits long (43 characters in
-- base64).
keyFromBase64 :: ByteString -- ^ URL-safe base64.
              -> Either String Key
keyFromBase64 = (>>= make) . b64urldec
  where make s = case key sk ek of
                   Just k -> Right k
                   Nothing -> Left "Invalid key length"
          where (sk, ek) = BS.splitAt ((BS.length s) - 16) s

-- | Stretches the given password into a 'Key' using PBKDF2.
generateKeyFromPassword :: Byteable p
                        => Int -- ^ Number of key derivation function iterations.
                        -> p   -- ^ The password.
                        -> IO (Key, ByteString) -- ^ The key and random salt used.
generateKeyFromPassword iterations p = do
  salt <- genSalt
  let keys = PBKDF2.generate prf params (toBytes p) salt
  return (splitKeys keys, salt)
  where
    prf = PBKDF2.prfHMAC SHA256
    params = PBKDF2.Parameters iterations 32
