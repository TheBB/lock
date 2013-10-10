-- {{{ Imports
import Codec.Encryption.AES (decrypt, encrypt)
import Codec.Encryption.Modes (cbc, unCbc)
import Codec.Encryption.Padding (pkcs5, unPkcs5)
import Control.Monad (when)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Maybe (MaybeT, runMaybeT)
import Control.Monad.State.Strict (StateT, evalStateT, get, put)
import Control.Monad.Trans (lift)
import Data.Bits ((.|.), shiftL, shiftR)
import Data.ByteString as BS (pack, readFile, unpack, writeFile, ByteString)
import Data.ByteString.UTF8 (fromString, toString)
import Data.Char (isDigit, digitToInt)
import Data.Maybe (isNothing)
import Data.LargeWord (Word128)
import Data.List (isPrefixOf, intercalate)
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

-- {{{ Types and monad transformers
data Status = Status {
                       statusFile :: FilePath
                     , encFile :: FilePath
                     , timeStarted :: Integer 
                     , timeUnlock :: Integer
                     }
    deriving (Read, Show)

type InputIO = InputT IO
type MaybeIO = MaybeT InputIO
type StateIO = StateT Status InputIO

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

showTime :: Integer -> String
showTime 0 = "0 seconds"
showTime n
    | length lst > 1 = (intercalate ", " . init) lst ++ " and " ++ last lst
    | otherwise = last lst
    where lst = accLst [] n
          accLst acc 0 = reverse acc
          accLst acc n = let (per, perStr) = getPer n
                             d = n `div` per
                             str = (show d ++ " " ++ perStr ++ (if d >= 1 then "s" else ""))
                         in accLst (str:acc) (n `mod` per)
          getPer n
              | n >= week = (week, "week")
              | n >= day = (day, "day")
              | n >= hour = (hour, "hour")
              | n >= minute = (minute, "minute")
              | n >= second = (second, "second")
          (week, day, hour, minute, second) = (7*24*60*60, 24*60*60, 60*60, 60, 1)
-- }}}

-- {{{ Start new session
startNewSession :: String -> MaybeIO Status
startNewSession fp = do
    initTime <- maybeRun (lift getTime)
    initLen <- maybeReadTime "Initial time to unlock: "
    plainText <- liftIO $ BS.readFile fp
    liftIO $ writeEncrypted (fp ++ ".enc") plainText
    return (Status (fp ++ ".st") (fp ++ ".enc") initTime (initTime + initLen))
-- }}}

-- {{{ Main program loop
writeStatus :: Status -> IO ()
writeStatus st = writeEncrypted (statusFile st) $ (fromString . show) st

writeStatusState :: StateIO ()
writeStatusState = get >>= liftIO . writeStatus

printStatus :: StateIO ()
printStatus = get >>= lift . outputStrLn . show

unlock :: StateIO ()
unlock = do
    st <- get
    time <- liftIO getTime
    case time of
        Nothing -> lift $ outputStrLn "Failed to get time."
        Just t -> if t >= timeUnlock st
                     then performUnlock >> lift (outputStrLn "Unlocked." >> exitSuccess)
                     else lift $ outputStrLn $ "Can't unlock for another " ++ showTime (timeUnlock st - t) ++ "."
    where performUnlock = do
              st <- get
              plainText <- liftIO $ readEncrypted $ encFile st
              liftIO $ BS.writeFile (encFile st ++ ".restored") plainText

commands = [
             ("help",       ("print this help", lift $ outputStrLn help))
           , ("exit",       ("save status to disk and exit", writeStatusState >> lift exitSuccess))
           , ("save",       ("save status to disk", writeStatusState))
           , ("unlock",     ("unlock and exit", unlock))
           , ("dbg",        ("print debugging information", printStatus))
           ]
help = let line = (\c -> fst c ++ replicate (15 - length (fst c)) ' ' ++ fst (snd c))
       in (intercalate "\n" . map line) commands

enterLoop :: StateIO ()
enterLoop = do
    lift $ outputStrLn "Type \"help\" for a list of commands."
    loop 

loop :: StateIO ()
loop = do
    inp <- lift $ getInputLine ">> "
    when (isNothing inp) (writeStatusState >> lift exitFailure)
    let Just s = inp
    case words s of
        [] -> loop
        (cmd:args) -> case lookup cmd commands of
                         Just act -> snd act >> loop
                         Nothing -> do
                             lift $ outputStrLn $ "Unrecognized command: '" ++ cmd ++ "'"
                             loop
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

searchFunc :: String -> [Completion]
searchFunc s = map simpleCompletion $ filter (s `isPrefixOf`) (map fst commands)
hlSettings = setComplete (completeWord Nothing " \t" $ return . searchFunc) defaultSettings

exitSuccess = lift System.Exit.exitSuccess :: InputIO a
exitFailure = lift System.Exit.exitFailure :: InputIO a

processFlags :: [Flag] -> InputIO ()
processFlags [] = return ()
processFlags (flag:flags) = processFlag flag >> processFlags flags

processFlag :: Flag -> InputIO ()
processFlag Version = outputStrLn version
processFlag Help = outputStrLn usage
processFlag (Image fp) = do
    status <- runMaybeT (startNewSession fp)
    case status of
        Nothing -> outputStrLn "Unable to start session" >> exitFailure
        Just st -> do
            lift $ writeStatus st
            evalStateT enterLoop st
processFlag (Session fp) = do
    bs <- lift $ readEncrypted (fp ++ ".st")
    let st = (read . toString) bs :: Status
    evalStateT enterLoop st

main :: IO ()
main = do
    args <- getArgs
    case getOpt RequireOrder options args of
        ([], [], [])     -> putStrLn usage
        (flags, [], [])  -> runInputT hlSettings (processFlags flags)
        (_, nonOpts, []) -> error $ "Unrecognized arguments: " ++ unwords nonOpts
        (_, _, msgs)     -> error $ concat msgs ++ usage
-- }}}
