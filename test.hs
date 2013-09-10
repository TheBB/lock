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
import Data.LargeWord (Word128)
import Data.Word (Word8)
-- }}}

key = 0x06a9214036b8a15b512e03d534120006 :: Word128
iv  = 0x3dafba429d9eb430b422da802c9fac41 :: Word128

{-plaintext = "This is a string with some vaguely specified length."-}

{-ciphertext = cbc encrypt iv key $ pkcs5 $ map (fromIntegral . ord) plaintext-}

{-plaintext' = map (chr . fromIntegral) $ unPkcs5 $ unCbc decrypt iv key ciphertext-}

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
    return $ unPkcs5 $ unCbc decrypt iv key (pkcs5 ciphertext)

writeEncrypted :: FilePath -> [Word8] -> IO ()
writeEncrypted fn bytes = do
    let ciphertext = cbc encrypt iv key (pkcs5 bytes)
    writePlain fn (unPkcs5 ciphertext)

dostuff :: IO ()
dostuff = do
    bytes <- loadPlain "test.txt"
    writeEncrypted "test-enc.txt" bytes

redostuff :: IO ()
redostuff = do
    bytes <- loadEncrypted "test-enc.txt"
    writePlain "test-dec.txt" bytes
