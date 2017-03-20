module Network.Fernet
  ( encrypt
  , decrypt
  , encrypt'
  , decrypt'
  , Key
  , key
  , generateKey
  , generateKeyFromPassword
  , keyFromBase64
  , keyToBase64
  , version
  ) where

import           Data.ByteString        (ByteString)
import qualified Data.ByteString        as BS
import           Data.ByteArray         (ScrubbedBytes)
import           Data.Byteable          (constEqBytes)
import           Data.Word              (Word8)
import           Data.Time.Clock        (NominalDiffTime)
import           Data.Time.Clock.POSIX  (POSIXTime, getPOSIXTime)

import Data.Bifunctor (first)

import Network.Fernet.Crypto
import Network.Fernet.Key
import Network.Fernet.Token

version :: Word8
version = 0x80

----------------------------------------------------------------------------
-- Encryption

encrypt :: Key -> ByteString -> IO ByteString
encrypt key text = do
  ts <- getPOSIXTime
  iv <- genIV
  return $ encrypt' key ts iv text

encrypt' :: Key          -- ^ Keys
         -> POSIXTime    -- ^ Timestamp
         -> ByteString   -- ^ Initialization Vector
         -> ByteString   -- ^ Plain text
         -> ByteString
encrypt' Key{..} ts iv text =
  case serialize <$> makeToken encryptionKey ts iv text of
    Just token -> encode token (sign signingKey token)
    Nothing -> "" -- this shouldn't happen

makeToken :: ScrubbedBytes     -- ^ Keys
          -> POSIXTime         -- ^ Timestamp
          -> ByteString        -- ^ Initialization Vector
          -> ByteString        -- ^ Plain text
          -> Maybe TokenFields
makeToken k ts iv text = TokenFields version ts iv <$> ct
  where ct = aesEncrypt k iv text

----------------------------------------------------------------------------
-- Decryption

data DecryptError = TokenMalformed     -- ^ The token could not be decoded into fields.
                  | TokenInvalid       -- ^ Signature verification failed.
                  | TokenExpired       -- ^ Token age exceeded given TTL value.
                  | UnacceptableClockSkew -- ^ Token timestamp is too far in the future.
                  | KeySizeInvalid     -- ^ The key was not suitable for decryption.
                  | InvalidBlockSize   -- ^ The ciphertext length was not a multiple of the block size.
                  | UnsupportedVersion -- ^ The version was not 0x80.
                  deriving (Show, Eq)

decrypt :: Key -> NominalDiffTime -> ByteString -> IO (Either DecryptError ByteString)
decrypt key ttl t = do
  now <- getPOSIXTime
  return $ decrypt' key ttl now t

decrypt' :: Key -> NominalDiffTime -> POSIXTime -> ByteString -> Either DecryptError ByteString
decrypt' Key{..} ttl now t = do
  (fields, tb, sig) <- first (const TokenMalformed) (decode t)
  checkVersion fields
  checkTimestamp now fields
  checkExpiry ttl now fields
  checkSignature signingKey tb sig
  checkInputSize fields
  case aesDecrypt encryptionKey (tfIV fields) (tfCiphertext fields) of
    Just text -> Right text
    Nothing -> Left KeySizeInvalid
  
checkVersion :: TokenFields -> Either DecryptError ()
checkVersion tf | tfVersion tf == version = Right ()
                | otherwise = Left UnsupportedVersion

-- | Maximum clock skew in the future direction.
maxClockSkew :: NominalDiffTime
maxClockSkew = 60

checkTimestamp :: POSIXTime -> TokenFields -> Either DecryptError ()
checkTimestamp now TokenFields{..} | tfTimestamp - now <= maxClockSkew = Right ()
                                   | otherwise = Left UnacceptableClockSkew
                                    
checkExpiry :: NominalDiffTime -> POSIXTime -> TokenFields -> Either DecryptError ()
checkExpiry ttl now TokenFields{..} | now - tfTimestamp < ttl = Right ()
                                    | otherwise = Left TokenExpired

checkSignature :: ScrubbedBytes -> ByteString -> ByteString -> Either DecryptError ()
checkSignature k tf sig | constEqBytes sig (sign k tf) = Right ()
                        | otherwise                    = Left TokenInvalid

checkInputSize :: TokenFields -> Either DecryptError ()
checkInputSize tf | isBlocked (tfCiphertext tf) = Right ()
                  | otherwise                   = Left InvalidBlockSize
  where isBlocked t = BS.length t `mod` cipherBlockSize == 0
