module Network.Fernet.Crypto
  ( sign
  , aesEncrypt
  , aesDecrypt
  , genIV
  , cipherBlockSize
  ) where

import           Data.ByteString        (ByteString)
import           Data.ByteArray         (ByteArray, ByteArrayAccess, convert)

import           Crypto.Data.Padding    (Format(PKCS7), pad, unpad)
import           Crypto.Hash.Algorithms (SHA256 (..))
import           Crypto.Cipher.AES      (AES128)
import           Crypto.MAC.HMAC        (HMAC(..), hmac, hmacGetDigest)
import           Crypto.Cipher.Types
import           Crypto.Error
import           Crypto.Random          (getRandomBytes)

import Network.Fernet.Token (Signature)

sign :: ByteArrayAccess a => a -> ByteString -> Signature
sign key t = convert $ hmacGetDigest (hmac key t :: HMAC SHA256)

aesEncrypt :: ByteArray a
           => a          -- ^ The encryption key
           -> ByteString -- ^ Initialization Vector
           -> ByteString -- ^ Plain text
           -> Maybe ByteString
aesEncrypt key iv text = cbcEncrypt <$> ctx <*> iv' <*> text'
  where
    ctx = maybeCryptoError (cipherInit key) :: Maybe AES128
    iv' = makeIV iv
    p = fmap (PKCS7 . blockSize) ctx
    text' = pad <$> p <*> pure text

aesDecrypt :: ByteArray a
           => a           -- ^ The encryption key
           -> ByteString -- ^ Initialization Vector
           -> ByteString -- ^ Cipher text
           -> Maybe ByteString
aesDecrypt key iv ct = do
  (ctx, iv', p) <- aesSetup key iv
  let text' = cbcDecrypt ctx iv' ct
  unpad p text'

-- | Block size for AES128
cipherBlockSize :: Int
cipherBlockSize = 16

genIV :: IO ByteString
genIV = getRandomBytes cipherBlockSize

aesSetup :: ByteArray a => a -> ByteString -> Maybe (AES128, IV AES128, Format)
aesSetup key iv = (,,) <$> ctx <*> iv' <*> p
  where
    ctx = maybeCryptoError (cipherInit key)
    iv' = makeIV iv
    p = PKCS7 . blockSize <$> ctx
