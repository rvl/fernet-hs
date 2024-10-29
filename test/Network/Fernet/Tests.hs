{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE DeriveGeneric #-}

module Network.Fernet.Tests (makeTests) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Char8 as S8
import Data.Maybe (fromJust, fromMaybe)
import Data.Either (isLeft)
import Data.Aeson hiding (Key)
import Control.Applicative
import Data.Time.Clock (NominalDiffTime)
import Data.Time.LocalTime (zonedTimeToUTC)
import Data.Time.Format (parseTimeM, defaultTimeLocale)
import Data.Time.Clock.POSIX (POSIXTime, utcTimeToPOSIXSeconds)
import GHC.Generics
import System.IO

import Test.QuickCheck
import Test.QuickCheck.Monadic
import qualified Test.QuickCheck         as QC
import qualified Test.QuickCheck.Monadic as QC
import           Test.Tasty              (TestTree, testGroup)
import           Test.Tasty.HUnit        (testCase)
import           Test.HUnit              (Assertion, (@?=), assertFailure)

import Network.Fernet

data Spec = Spec
            { desc :: String
            , token :: ByteString
            , now :: POSIXTime
            , ttl :: NominalDiffTime
            , secret :: ByteString
            , src :: ByteString
            , iv :: ByteString
            } deriving (Generic, Show)

instance FromJSON Spec where
    parseJSON = withObject "Spec" $ \v -> Spec
        <$> v .:? "desc" .!= ""
        <*> liftA S8.pack (v .: "token")
        <*> liftA (fromMaybe 0 . parseTime) (v .: "now")
        <*> liftA (fromIntegral :: Int -> NominalDiffTime) (v .:? "ttl_sec" .!= 0)
        <*> liftA S8.pack (v .: "secret")
        <*> liftA S8.pack (v .:? "src" .!= "")
        <*> liftA BS.pack (v .:? "iv" .!= [])

parseTime :: MonadFail m => String -> m POSIXTime
parseTime = fmap (utcTimeToPOSIXSeconds . zonedTimeToUTC) . parseTimeM False defaultTimeLocale fmt
  where fmt = "%Y-%m-%dT%H:%M:%S%z"

makeTests :: IO TestTree
makeTests = do
  generate <- makeGroup "generate" generateTest
  verify <- makeGroup "verify" verifyTest
  invalid <- makeGroup "invalid" invalidTest
  return $ testGroup "Acceptance Tests" [ generate, verify, invalid ]

makeGroup :: String -> (Spec -> TestTree) -> IO TestTree
makeGroup name makeSpec = do
  let f = "spec/" ++ name ++ ".json"
  withFile f ReadMode $ \h -> do
    c <- BL.hGetContents h
    case eitherDecode' c of
      Right specs -> return $ testGroup name (map makeSpec specs)
      Left e -> return $ testGroup name [testCase ("Loading " ++ f) (assertFailure e)]

getKey :: ByteString -> IO Key
getKey secret = case keyFromBase64 secret of
                  Right key -> return key
                  Left e -> fail $ "Couldn't decode secret: " ++ e

generateTest :: Spec -> TestTree
generateTest Spec{..} = testCase "Token generation" $ do
  key <- getKey secret
  encrypt' key now iv src @?= token

verifyTest :: Spec -> TestTree
verifyTest Spec{..} = testCase "Successful token verification" $ do
  key <- getKey secret
  decrypt' key ttl now token @?= Right src

invalidTest :: Spec -> TestTree
invalidTest Spec{..} = testCase desc $ do
  key <- getKey secret
  let r = decrypt' key ttl now token
  isLeft r @?= True
  
