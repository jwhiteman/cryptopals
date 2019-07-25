# https://cryptopals.com/sets/3/challenges/21
#
# https://en.wikipedia.org/wiki/Mersenne_Twister
#
require_relative "../test_helper"

module Set3
  class MT19937
    W          = 32
    N          = 624
    M          = 397
    R          = 31
    F          = 1812433253 # 69069

    LOWER_MASK = 0x7FFF_FFFF # (1 << R) - 1
    UPPER_MASK = 0x8000_0000 # ~LOWER_MASK

    U          = 11
    S          = 7
    T          = 15
    L          = 18
    D          = 0xFFFF_FFFF
    B          = 0x9D2C_5680
    C          = 0xEFC6_0000

    A          = 0x9908_B0DF

    attr_accessor :mt
    attr_accessor :index

    def initialize(seed)
      @mt    = []
      @mt[0] = seed

      (1..(N-1)).each do |i|
        @mt[i] =
          (F * (@mt[i-1] ^ (@mt[i-1] >> (W-2))) + i) & 0xFFFF_FFFF
      end

      @index = N
    end

    def rand
      twist if index == N

      y = mt[index]
      y = y ^ ((y >> U) & D)
      y = y ^ ((y << S) & B)
      y = y ^ ((y << T) & C)
      y = y ^ (y >> L)
      self.index = index + 1

      y & 0xFFFF_FFFF
    end

    private

    def twist
      (0..(N-1)).each do |i|
        x  = (mt[i] & UPPER_MASK) + (mt[(i+1) % N] & LOWER_MASK)
        xA = x >> 1
        if x % 2 != 0
          xA = xA ^ A
        end

        self.mt[i] = mt[(i + M) % N] ^ xA
      end

      self.index = 0
    end
  end

  class Challenge21Test < Test::Unit::TestCase
    def test_challenge_21
      prng = MT19937.new(5489)

      assert_equal prng.rand, 3499211612
      assert_equal prng.rand, 581869302
      assert_equal prng.rand, 3890346734
      assert_equal prng.rand, 3586334585
      assert_equal prng.rand, 545404204
      assert_equal prng.rand, 4161255391
      assert_equal prng.rand, 3922919429
      assert_equal prng.rand, 949333985
      assert_equal prng.rand, 2715962298
      assert_equal prng.rand, 1323567403
    end
  end
end
