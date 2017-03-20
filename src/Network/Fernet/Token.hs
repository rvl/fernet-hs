module Network.Fernet.Token
  ( encode
  , decode
  , serialize
  , deserialize
  , TokenFields(..)
  , Signature
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString        as BS
import qualified Data.ByteString.Lazy   as BL

import Data.Word (Word8)
import Data.Time.Clock.POSIX  (POSIXTime)
import Data.Binary.Get
import Data.Binary.Put

import Network.Fernet.Base64

data TokenFields = TokenFields
  { tfVersion    :: Word8      -- ^ Version, 8 bits
  , tfTimestamp  :: POSIXTime  -- ^ Timestamp, 64 bits
  , tfIV         :: ByteString -- ^ IV, 128 bits
  , tfCiphertext :: ByteString -- ^ Ciphertext, variable length, multiple of 128 bits
  } deriving (Show, Eq)

type Signature = ByteString

-- | Size of a SHA256 hash.
hmacLength :: Int
hmacLength = 32

encode :: ByteString -> Signature -> ByteString
encode t s = b64url $ BS.concat [t, s]

decode :: ByteString -> Either String (TokenFields, ByteString, Signature)
decode = (>>= decode') . b64urldec
  where
    decode' bs = do
      (t, sig) <- splitToken bs
      tf <- deserialize t
      return (tf, t, sig)
    splitToken bs | BS.length sig < hmacLength = Left "Missing HMAC"
                  | otherwise = Right (t, sig)
      where (t, sig) = BS.splitAt (BS.length bs - hmacLength) bs

serialize :: TokenFields -> ByteString
serialize TokenFields{..} = BL.toStrict . runPut $ do
  putWord8 tfVersion
  putWord64be (floor tfTimestamp)
  putByteString tfIV
  putByteString tfCiphertext

deserialize :: ByteString -> Either String TokenFields
deserialize t = case runGetOrFail get (BL.fromStrict t) of
                  Left (_, _, e) -> Left e
                  Right (_, _, tf) -> Right tf
  where get = do
          v <- getWord8
          ts <- getWord64be
          iv <- getByteString 16
          ct <- BL.toStrict <$> getRemainingLazyByteString
          return $! TokenFields v (fromIntegral ts) iv ct
