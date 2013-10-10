-- {{{ Imports
import Codec.Encryption.AES (decrypt, encrypt)
import Codec.Encryption.Modes (cbc, unCbc)
import Codec.Encryption.Padding (pkcs5, unPkcs5)
import Control.Monad.Maybe (MaybeT, runMaybeT)
import Control.Monad.Trans (lift)
import Data.Bits ((.|.), shiftL, shiftR)
import Data.ByteString as BS (pack, readFile, unpack, writeFile, ByteString)
import Data.Char (isDigit, digitToInt)
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

version = "lock version 0.0.1"

-- {{{ Monad transformers
type InputIO = InputT IO
type MaybeIO = MaybeT InputIO

maybeRun :: InputIO (Maybe a) -> MaybeIO a
maybeRun act = do
    res <- lift act
    case res of
        Nothing -> fail ""
        Just s -> return s
-- }}}

-- {{{ Encryption
key = 0x06a9214036b8a15b512e03d534120006 :: Word128
iv  = 0x3dafba429d9eb430b422da802c9fac41 :: Word128

readEncrypted :: FilePath -> IO ByteString
readEncrypted fn = do
    ciphertext <- BS.readFile fn
    return $ pack $ unPkcs5 $ unCbc decrypt iv key $ (bytesToWords . unpack) ciphertext

writeEncrypted :: FilePath -> ByteString -> IO ()
writeEncrypted fn bytes = do
    let ciphertext = cbc encrypt iv key $ (pkcs5 . unpack) bytes
    BS.writeFile fn $ (pack . wordsToBytes) ciphertext

dostuff :: IO ()
dostuff = do
    bytes <- BS.readFile "test.txt"
    writeEncrypted "test-enc.txt" bytes

redostuff :: IO ()
redostuff = do
    bytes <- readEncrypted "test-enc.txt"
    BS.writeFile "test-dec.txt" bytes

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

timeMults = [('s', 1), ('m', 60), ('h', 60*60), ('d', 24*60*60), ('w', 7*24*60*60)]
parseTime :: String -> Maybe Integer
parseTime = parseAcc 0 0
    where parseAcc glob loc (c:cs)
              | isDigit c = parseAcc glob (10*loc + fromIntegral (digitToInt c)) cs
              | c `elem` "smhdw" = let Just mul = lookup c timeMults
                              in parseAcc (glob + mul*loc) 0 cs
              | otherwise = Nothing
          parseAcc glob loc [] = Just (glob + loc)

maybeReadTime :: String -> MaybeIO Integer
maybeReadTime prompt = do
    inp <- maybeRun (getInputLine prompt)
    let time = parseTime inp
    case time of
        Nothing -> fail "Unable to parse time"
        Just t -> return t
-- }}}

-- {{{ Lock status
data Status = Status {
                       timeStarted :: Integer 
                     , timeUnlock :: Integer
                     }
    deriving (Read, Show)
-- }}}

-- {{{ Start new session
startNewSession :: String -> MaybeIO Status
startNewSession fp = do
    initTime <- maybeRun (lift getTime)
    initLen <- maybeReadTime "Initial time to unlock: "
    return (Status initTime (initTime + initLen))
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

exitSuccess = lift System.Exit.exitSuccess :: InputIO a
exitFailure = lift System.Exit.exitFailure :: InputIO a

processFlags :: [Flag] -> InputIO ()
processFlags [] = return ()
processFlags (flag:flags) = processFlag flag >> processFlags flags

processFlag :: Flag -> InputIO ()
processFlag Version = outputStrLn version >> exitSuccess
processFlag Help = outputStrLn usage >> exitSuccess
processFlag (Image fp) = do
    status <- runMaybeT (startNewSession fp)
    case status of
        Nothing -> outputStrLn "Unable to start session" >> exitFailure
        Just st -> outputStrLn (show st) >> exitSuccess
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
