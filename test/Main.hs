module Main where

import           Test.Tasty (defaultMain, testGroup)

import qualified Network.Fernet.Tests

main :: IO ()
main = do
  tests <- Network.Fernet.Tests.makeTests
  defaultMain $ testGroup "Tests" [ tests ]
