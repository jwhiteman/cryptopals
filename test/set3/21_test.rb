# https://cryptopals.com/sets/3/challenges/21
#
# https://en.wikipedia.org/wiki/Mersenne_Twister
# https://www.techotopia.com/index.php/Ruby_Operators#Ruby_Bitwise_Operators
# https://stackoverflow.com/questions/3270307/how-do-i-get-the-lower-8-bits-of-int
# https://create.stephan-brumme.com/mersenne-twister/
#
require_relative "../test_helper"

module Set3
  class MersenneTwister
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
    D          = 0xFFFF_FFFF
    B          = 0x9D2C_5680
    C          = 0xEFC6_0000

    A          = 0x9908_B0DF

    attr_accessor :mt
    attr_accessor :index

    def initialize
      @mt    = []
      @index = N + 1
    end

    def seed_mt(seed)
      self.index = N
      self.mt[0] = seed

      (1..(N-1)).each do |i|
        self.mt[i] =
          (F * (mt[i-1] ^ (mt[i-1] >> (W-2))) + i) & 0xFFFF_FFFF
      end
    end

    def extract_number
      if index >= N
        if index > N
          raise "Generator was never seeded"
        else
          twist
        end
      end

      y = mt[index]
      y = y ^ ((y >> U) & D)
      y = y ^ ((y << S) & B)
      y = y ^ ((y >> T) & C)
      y = y ^ (y >> 1)

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

    def inspect
      "<PRNG>"
    end
  end

  class Challenge21Test < Test::Unit::TestCase
    def test_challenge_21
      prng = MersenneTwister.new

      prng.seed_mt(5489)

      results = 10.times.map { prng.extract_number }

      binding.pry
    end
  end
end
