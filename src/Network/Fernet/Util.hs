module Network.Fernet.Util
  ( randomBytes
  ) where

import           Data.ByteString        (ByteString)
import Crypto.Random (DRG, getSystemDRG, withRandomBytes)

randomBytesGen :: DRG gen => Int -> gen -> (ByteString, gen)
randomBytesGen n gen = withRandomBytes gen n id

randomBytes :: Int -> IO ByteString
randomBytes n = fst . randomBytesGen n <$> getSystemDRG
