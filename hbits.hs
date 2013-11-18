import qualified ECDSA
import SHA256
import Numeric
import Data.Char
import Data.Vector.Unboxed
import qualified Data.ByteString.Char8 as BC

toString n = showIntAtBase 16 intToDigit n ""

main :: IO ()
main = do
  putStrLn "hello, world"
  putStrLn $ sha256 (BC.pack "The quick brown fox jumps over the lazy dog")
