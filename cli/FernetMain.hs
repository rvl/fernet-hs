module Main where

import Options.Applicative
import Data.Monoid ((<>))
import Control.Monad (join, unless, when)
import Data.Time.Clock (NominalDiffTime)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Char8 as S8
import qualified Data.ByteString.Lazy.Char8 as L8
import qualified Data.ByteArray.Encoding as B (Base(..), convertFromBase)
import Text.Read (readEither)
import System.IO
import Data.Bifunctor (first)
import System.Posix.IO (handleToFd, stdInput)
import System.Posix.Terminal (queryTerminal)

import Network.Fernet

main :: IO ()
main = join . execParser $
  info (helper <*> parser)
  (  fullDesc
  <> header "Fernet Utility"
  <> progDesc "Encrypts/decrypts Fernet tokens. One token per line of input."
  )
  where
    parser :: Parser (IO ())
    parser =
      (fernet
        <$> (KeyText <$> ( strOption
              ( long "key"
                <> short 'k'
                <> metavar "STRING"
                <> help "Base64-encoded encryption keys"
              )) <|>
              KeyFile <$> ( strOption
                ( long "key-file"
                  <> metavar "FILENAME"
                  <> help "File containing base64-encoded keys"
                )
              ))
        <*> ( optional
              ( flag' Encrypt
                ( long "encrypt"
                  <> short 'e'
                  <> help "Encrypt input" )
              <|>
              flag' Decrypt
                ( long "decrypt"
                  <> short 'd'
                  <> help "Decrypt input" )
              )
            )
        <*> option ttl
            ( long "ttl"
            <> metavar "SECONDS"
            <> help "Token lifetime in seconds (default: 0 -- infinite)"
            <> value 0
            )) <|>
      (genKey <$> ( flag' True
                    (long "gen-key"
                    <> short 'g'
                    <> help "Generate a key from the password on standard input"
                    )))
{-
(PasswordText <$> ( strOption
              ( long "password"
                <> short 'p'
                <> metavar "STRING"
                <> help "Encrypting/signing password"
              )) <|>
              PasswordFile <$> ( strOption
                ( long "password-file"
                  <> metavar "FILENAME"
                  <> help "File containing encryption/signing password"
                )
              ))
-}

genKey :: Bool -> IO ()
genKey _ = do
  password <- askPassword
  k <- generateKeyFromPassword iterations password
  S8.hPutStrLn stdout (keyToBase64 k)

askPassword ::  IO ByteString
askPassword = do
  isatty <- queryTerminal stdInput
  when isatty $ do
    hSetEcho stdin False
    S8.hPutStr stderr "Enter password: "
    hFlush stdout
  password <- S8.hGetLine stdin
  when isatty $ do
    hSetEcho stdin True
    S8.hPut stderr "\n"
  return password

ttl :: ReadM NominalDiffTime
ttl = eitherReader (fmap fromInteger . readEither)

data Action = Encrypt | Decrypt
data Keys = KeyText String | KeyFile FilePath
data Password = PasswordText String | PasswordFile FilePath

fernet :: Keys -> Maybe Action -> NominalDiffTime -> IO ()
fernet ks ax ttl = do
  k <- readKeys ks
  L8.hGetContents stdin >>= mapM_ (processLine k ax ttl) . L8.lines

processLine :: Key -> Maybe Action -> NominalDiffTime -> L8.ByteString -> IO ()
processLine k ax ttl s = doLine k ax ttl s >>= uncurry L8.hPutStrLn . output

output :: Either String ByteString -> (Handle, L8.ByteString)
output (Left e)  = (stderr, L8.pack e)
output (Right s) = (stdout, L8.fromStrict s)

doLine :: Key -> Maybe Action -> NominalDiffTime -> L8.ByteString -> IO (Either String ByteString)
doLine k (Just Encrypt) _   s = lineEncrypt k s
doLine k (Just Decrypt) ttl s = lineDecrypt k ttl s
doLine k Nothing        ttl s = doLine k (Just $ sniff s) ttl s

sniff :: BL.ByteString -> Action
sniff s | ver >= "gA" && ver <= "gP" = Decrypt
        | otherwise                  = Encrypt
  where ver = BL.take 2 s

lineEncrypt :: Key -> L8.ByteString -> IO (Either String ByteString)
lineEncrypt k s = Right <$> encrypt k (L8.toStrict s)

lineDecrypt :: Key -> NominalDiffTime -> L8.ByteString -> IO (Either String ByteString)
lineDecrypt k ttl s = first show <$> decrypt k ttl (L8.toStrict s)

readKeys :: Keys -> IO Key
readKeys (KeyText k) = keyFromString k
readKeys (KeyFile f) = readFirstLine f >>= \k -> readKeys (KeyText k)

readPassword :: Password -> IO Key
readPassword (PasswordText p) = generateKeyFromPassword iterations (S8.pack p)
readPassword (PasswordFile f) = readFirstLine f >>= \p -> readPassword (PasswordText p)

iterations = 100000 :: Int

readFirstLine :: FilePath -> IO String
readFirstLine f = withFile f ReadMode hGetLine

keyFromString :: String -> IO Key
keyFromString s = case keyFromBase64 (S8.pack s) of
                    Right k -> return k
                    Left e -> fail e

-- | Converts 'Maybe' to 'Either'.
justRight :: e -> Maybe a -> Either e a
justRight _ (Just a) = Right a
justRight e Nothing = Left e
