{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ExistentialQuantification #-}
module Main where

import Control.Applicative
import Control.Monad

import Test.Framework (Test, defaultMain, testGroup)
import Test.Framework.Providers.QuickCheck2 (testProperty)
import Test.Framework.Providers.HUnit (testCase)
import Test.HUnit

import Test.QuickCheck
import Test.QuickCheck.Test
import Test.Framework.Providers.QuickCheck2 (testProperty)

import qualified Crypto.Data.AFIS as AFIS
import Crypto.Hash
import Crypto.Random.API
import qualified Data.ByteString as B

import Text.Bytedump

mergeVec =
    [ (3
      , hash :: HashFunctionBS SHA1
      , "\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02"
      , "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\xd4\x76\xc8\x58\xbd\xf0\x15\xbe\x9f\x40\xe3\x65\x20\x1c\x9c\xb8\xd8\x1c\x16\x64"
      )
    , (3
      , hash :: HashFunctionBS SHA1
      , "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17"
      , "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\xd6\x75\xc8\x59\xbb\xf7\x11\xbb\x95\x4b\xeb\x6c\x2e\x13\x90\xb5\xca\x0f\x06\x75\x17\x70\x39\x28"
      )
    ]

mergeKATs = map toProp $ zip mergeVec [0..]
  where toProp ((nbExpands, hashF, expected, dat), i) =
            testCase ("merge " ++ show i) (expected @=? AFIS.merge hashF nbExpands dat)

data AFISParams = forall a . HashAlgorithm a => AFISParams B.ByteString Int (HashFunctionBS a) FakeRNG

instance Show AFISParams where
    show (AFISParams dat expand _ _) = "data: " ++ show dat ++ " expanded: " ++ show expand

data FakeRNG = FakeRNG Int B.ByteString

instance CPRG FakeRNG where
    cprgNeedReseed _ = NeverReseed
    cprgSupplyEntropy b2 (FakeRNG o b) = FakeRNG o (B.append b b2)
    cprgGenBytes n (FakeRNG o b)
        | n > B.length b - o = (B.take n $ B.drop o (B.concat $ replicate 10 b), FakeRNG 0 b)
        | otherwise          = (B.take n $ B.drop o b, FakeRNG (o+n) b)

instance Arbitrary AFISParams where
    arbitrary = AFISParams <$> arbitraryBS <*> choose (2,2) <*> elements [hash :: HashFunctionBS SHA1] <*> arbitraryRandom
      where arbitraryBS = choose (3,46) >>= \sz -> B.pack <$> replicateM sz arbitrary 
            arbitraryRandom = choose (1024,4096) >>= \sz -> FakeRNG 0 . B.pack <$> replicateM sz arbitrary

tests =
    [ testGroup "KAT merge" mergeKATs
    , testProperty "merge.split == id" $ \(AFISParams bs e hf rng) -> (AFIS.merge hf e $ fst (AFIS.split hf rng e bs)) `assertEq` bs
    ]

assertEq :: B.ByteString -> B.ByteString -> Bool
assertEq b1 b2 | b1 /= b2  = error ("b1: " ++ show b1 ++ " b2: " ++ show b2)
               | otherwise = True

main = defaultMain tests
{-
    let hf    = hash :: HashFunctionBS SHA1
        e     = 4
        bs    = B.pack [1,2,3,4,5,1,2]
        (z,_) = AFIS.split hf (FakeRNG 0 $ B.replicate 4000 3) e bs
        bs2   = AFIS.merge hf e z
    when (bs /= bs2) $ do
        putStrLn ("bs : " ++ dumpRawBS bs)
        putStrLn ("z  : " ++ dumpRawBS z)
        putStrLn ("bs2: " ++ dumpRawBS bs2)
-}
