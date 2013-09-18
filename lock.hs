-- {{{ Imports
import Codec.Encryption.AES ( 
                              decrypt
                            , encrypt
                            )
import Codec.Encryption.Modes ( 
                                cbc
                              , unCbc
                              )
import Codec.Encryption.Padding (
                                  pkcs5
                                , unPkcs5
                                )
import Data.ByteString as BS (
                               pack
                             , readFile
                             , unpack
                             , writeFile
                             )
import Data.Char ( 
                   ord
                 , chr
                 )
import Data.Maybe (isNothing)
import Data.LargeWord (Word128)
import Data.List.Split (chunksOf)
import Data.Word (Word8)
import Network.HTTP ( 
                      getResponseBody
                    , getRequest
                    , simpleHTTP
                    )
import Numeric (showHex)
import Text.Regex (
                    matchRegex
                  , mkRegex
                  )
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

wordToString :: Word128 -> String
wordToString w = replicate (32 - length s) '0' ++ s
    where s = showHex (fromIntegral w) ""

stringToWord :: String -> Word128
stringToWord s = fromIntegral (read ("0x" ++ s))

stringToBytes :: String -> [Word8]
stringToBytes "" = []
stringToBytes [a] = []
stringToBytes (a:b:ss) = (read ("0x" ++ [a,b])) : stringToBytes ss

byteToString :: Word8 -> String
byteToString b = replicate (2 - length s) '0' ++ s
    where s = showHex b ""

bytesToString :: [Word8] -> String
bytesToString = concat . (map byteToString)

wordsToBytes = concat . map (stringToBytes . wordToString)

bytesToWords :: [Word8] -> [Word128]
bytesToWords bs = map (stringToWord . bytesToString) $ chunksOf 16 bs

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
