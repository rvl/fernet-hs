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

import Network.Fernet.Base64
import Network.Fernet.Util

-- | Contains the signing key and encryption key. Create a 'Key' with 'key'.
data Key = Key
           { signingKey    :: ScrubbedBytes
           , encryptionKey :: ScrubbedBytes
           } deriving (Show, Eq)

-- | Constructs a pair of signing and encryption keys.
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

generateKey :: IO ByteString
generateKey = b64url <$> generateKeyBytes

generateKeyBytes :: IO ByteString
generateKeyBytes = randomBytes cipherKeyLength

genSalt :: IO ByteString
genSalt = randomBytes 16

keyToBase64 :: Key -> ByteString
keyToBase64 (Key s e) = b64url $ s <> e

keyFromBase64 :: ByteString -> Either String Key
keyFromBase64 = (>>= make) . b64urldec
  where make s = case key sk ek of
                   Just k -> Right k
                   Nothing -> Left "Invalid key length"
          where (sk, ek) = BS.splitAt ((BS.length s) - 16) s

generateKeyFromPassword :: Byteable p => Int -> p -> IO Key
generateKeyFromPassword iterations p = do
  salt <- genSalt
  let keys = PBKDF2.generate prf params (toBytes p) salt
      (sk, ek) = BS.splitAt 16 keys
  return $ Key (BA.convert sk) (BA.convert ek)
  where
    prf = PBKDF2.prfHMAC SHA256
    params = PBKDF2.Parameters iterations 32
