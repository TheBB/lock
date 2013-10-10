-- {{{ Imports
import Codec.Encryption.AES (decrypt, encrypt)
import Codec.Encryption.Modes (cbc, unCbc)
import Codec.Encryption.Padding (pkcs5, unPkcs5)
import Control.Monad.Trans (lift)
import Data.Bits ((.|.), shiftL, shiftR)
import Data.ByteString as BS (pack, readFile, unpack, writeFile)
import Data.Maybe (isNothing)
import Data.LargeWord (Word128)
import Data.List (isPrefixOf)
import Data.List.Split (chunksOf)
import Data.Word (Word8)
import Network.HTTP (getResponseBody, getRequest, simpleHTTP)
import System (getArgs)
import System.Console.GetOpt 
    ( 
      getOpt
    , usageInfo
    , ArgOrder (RequireOrder)
    , OptDescr (Option)
    , ArgDescr (NoArg, ReqArg)
    )
import System.Console.Haskeline 
    (
      defaultSettings
    , runInputT
    , outputStrLn
    , getInputLine
    , setComplete
    , InputT
    )
import System.Console.Haskeline.Completion (completeWord, simpleCompletion, Completion)
import qualified System.Exit (exitSuccess, exitFailure)
import Text.Regex (matchRegex, mkRegex)
-- }}}

-- {{{ Encryption
key = 0x06a9214036b8a15b512e03d534120006 :: Word128
iv  = 0x3dafba429d9eb430b422da802c9fac41 :: Word128

loadPlain :: FilePath -> IO [Word8]
loadPlain fn = do
    plain <- BS.readFile fn
    return (BS.unpack plain)

writePlain :: FilePath -> [Word8] -> IO ()
writePlain fn bytes = do
    BS.writeFile fn (BS.pack bytes)

loadEncrypted :: FilePath -> IO [Word8]
loadEncrypted fn = do
    ciphertext <- loadPlain fn
    return $ unPkcs5 $ unCbc decrypt iv key (bytesToWords ciphertext)

writeEncrypted :: FilePath -> [Word8] -> IO ()
writeEncrypted fn bytes = do
    let ciphertext = cbc encrypt iv key (pkcs5 bytes)
    writePlain fn (wordsToBytes ciphertext)

dostuff :: IO ()
dostuff = do
    bytes <- loadPlain "test.txt"
    writeEncrypted "test-enc.txt" bytes

redostuff :: IO ()
redostuff = do
    bytes <- loadEncrypted "test-enc.txt"
    writePlain "test-dec.txt" bytes

fixshiftR :: Word128 -> Int -> Word128
fixshiftR w s = fromIntegral $ (fromIntegral w :: Integer) `shiftR` s

shifts128 = [120, 112, 104, 96, 88, 80, 72, 64, 56, 48, 40, 32, 24, 16, 8, 0]
wordToBytes :: Word128 -> [Word8]
wordToBytes w = [fromIntegral (w `fixshiftR` k) | k <- shifts128]

bytesToWord :: [Word8] -> Word128
bytesToWord = foldl accum 0
    where accum a b = (a `shiftL` 8) .|. fromIntegral b

wordsToBytes = concat . (map wordToBytes)

bytesToWords = (map bytesToWord) . chunksOf 16
-- }}}

-- {{{ Time
getTimeSite :: String -> String -> IO (Maybe Integer)
getTimeSite uri regex = do
    rsp <- simpleHTTP (getRequest uri)
    txt <- getResponseBody rsp
    let matches = map (matchRegex (mkRegex regex)) $ lines txt
    case filter (not . isNothing) matches of
        ((Just m):_) -> return $ Just ((read . head) m :: Integer)
        [] -> return Nothing

getTime :: IO (Maybe Integer)
getTime = do
    cts <- getTimeCTS
    case cts of
        Just a -> return $ Just a
        Nothing -> getTimeUTS
    where getTimeCTS = getTimeSite "http://www.currenttimestamp.com/" "\\s*current_time\\s*=\\s*([0-9]+);\\s*"
          getTimeUTS = getTimeSite "http://www.unixtimestamp.com/" "\\s*([0-9]+)\\s*UTC"
-- }}}

-- {{{ Lock status
data Status = Status { timeStarted :: Integer }
    deriving (Read, Show)
-- }}}

-- {{{ Start new session
startNewSession :: FilePath -> InputT IO ()
startNewSession fp = do
    inp <- getInputLine "Initial time to release: "
    case inp of
        Nothing -> return ()
        Just s -> outputStrLn s
-- }}}

-- {{{ Main option processing and Haskeline settings
data Flag = Version | Help | Image FilePath | Session FilePath

options :: [OptDescr Flag]
options = [ 
            Option []    ["version"]    (NoArg Version)             "show version number" 
          , Option []    ["help"]       (NoArg Help)                "show version number" 
          , Option ['i'] ["image"]      (ReqArg Image "FILE")       "start new session"
          , Option ['s'] ["session"]    (ReqArg Session "FILE")     "open existing session"
          ]

usage = usageInfo "Usage: lock OPTION" options

wordList = ["alfa", "bravo", "charlie", "chinchilla"]
searchFunc :: String -> [Completion]
searchFunc s = map simpleCompletion $ filter (s `isPrefixOf`) wordList
hlSettings = setComplete (completeWord Nothing " \t" $ return . searchFunc) defaultSettings

exitSuccess = lift System.Exit.exitSuccess :: InputT IO a
exitFailure = lift System.Exit.exitFailure :: InputT IO a

processFlags :: [Flag] -> InputT IO ()
processFlags [] = return ()
processFlags (flag:flags) = processFlag flag >> processFlags flags

processFlag :: Flag -> InputT IO ()
processFlag Version = outputStrLn "v 0.1" >> exitSuccess
processFlag Help = outputStrLn usage >> exitSuccess
processFlag (Image fp) = startNewSession fp >> exitSuccess
processFlag (Session fp) = outputStrLn ("Session: " ++ fp) >> exitSuccess

main :: IO ()
main = do
    args <- getArgs
    case getOpt RequireOrder options args of
        ([], [], [])     -> putStrLn usage
        (flags, [], [])  -> runInputT hlSettings (processFlags flags)
        (_, nonOpts, []) -> error $ "Unrecognized arguments: " ++ unwords nonOpts
        (_, _, msgs)     -> error $ concat msgs ++ usage
-- }}}
