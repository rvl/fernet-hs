-- | Base64 utilities

module Network.Fernet.Base64 (
  -- * Base64
    b64
  , b64dec
  , b64url
  , b64urldec
  ) where

import Data.Monoid ((<>))
import qualified Data.ByteString.Char8   as S8
import           Data.ByteArray          (ByteArrayAccess)
import qualified Data.ByteArray.Encoding as B (Base (..), convertToBase, convertFromBase)
import           Data.ByteString         (ByteString)

-- | Shorthand for encode in Base64.
b64 :: ByteArrayAccess a => a -> ByteString
b64 = B.convertToBase B.Base64

b64url :: ByteArrayAccess a => a -> ByteString
b64url = urlSafeBase64 . b64

b64dec :: ByteArrayAccess a => a -> Either String ByteString
b64dec = B.convertFromBase B.Base64

b64urldec :: ByteString -> Either String ByteString
b64urldec = b64dec . unUrlSafeBase64

-- | Fixes up a Base64 encoded string so that it's more convenient to
-- include in URLs.
-- The characters @+@ and @/@ are replaced with @-@ and @_@.
urlSafeBase64 :: ByteString -> ByteString
urlSafeBase64 = S8.map (tr '+' '-' . tr '/' '_')

-- | The inverse of 'urlSafeBase64'.
unUrlSafeBase64 :: ByteString -> ByteString
unUrlSafeBase64 = S8.map (tr '-' '+' . tr '_' '/')

tr :: Char -> Char -> Char -> Char
tr a b c = if c == a then b else c
