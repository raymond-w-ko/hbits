-- adapted from http://en.wikipedia.org/wiki/SHA-2

module SHA256 (sha256) where

import Data.Word
import Data.Char
import Data.Bits
import qualified Data.Vector.Unboxed as Vector
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString as S
import qualified Numeric

-- Note 1: All variables are 32 bit unsigned integers and addition is
-- calculated modulo 2^32
--
-- Note 2: For each round, there is one round constant k[i] and one entry in
-- the message schedule array w[i], 0 <= i <= 63
--
-- Note 3: The compression function uses 8 working variables, a through h
--
-- Note 4: Big-endian convention is used when expressing the constants in this
-- pseudocode, and when parsing message block data from bytes to words, for
-- example, the first word of the input message "abc" after padding is
-- 0x61626380

-- Initialize hash values:
-- (first 32 bits of the fractional parts of the square roots of the first 8
-- primes 2..19):
h0 = 0x6a09e667
h1 = 0xbb67ae85
h2 = 0x3c6ef372
h3 = 0xa54ff53a
h4 = 0x510e527f
h5 = 0x9b05688c
h6 = 0x1f83d9ab
h7 = 0x5be0cd19

k :: Vector.Vector Word32
k = Vector.fromList 
  [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ]

hexString = S.concatMap $ \c -> BC.pack $ pad $ Numeric.showHex c []
            where
              pad [x] = ['0', x]
              pad s = s

int64ToByteString n =
  go BC.empty n 8
  where
    go acc n roundsLeft
       | roundsLeft == 0 = acc
       | otherwise = go (BC.cons (chr (n .&. 0xFF)) acc)
                        (n `shiftR` 8)
                        (roundsLeft - 1)

-- Pre-processing:
--
-- append the bit '1' to the message
--
-- append k bits '0', where k is the minimum number >= 0 such that the
-- resulting message length (modulo 512 in bits) is 448.
--
-- append length of message (before pre-processing), in bits, as 64-bit big-endian integer
preprocess :: BC.ByteString -> BC.ByteString
preprocess bs =
  let msgLenInBits = (BC.length bs) * 8
      modLen = (msgLenInBits + 1) `mod` 512
      moreBits = if modLen <= 448
                 then 448 - modLen
                 else (modLen - 448) + 448
      moreBytes = (moreBits + 1) `div` 8
      prefix = (BC.singleton (chr 0xA0))
      suffix = (BC.replicate (moreBytes - 1) (chr 0x00))
  in foldr1 BC.append [bs, (BC.append prefix suffix), (int64ToByteString msgLenInBits)]

sha256 msg =
  let finalmsg = preprocess msg 
  in BC.unpack $ hexString finalmsg
