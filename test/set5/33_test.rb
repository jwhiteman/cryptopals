# https://cryptopals.com/sets/5/challenges/33
require_relative "../test_helper"

module Set5
  class Challenge33Test < Test::Unit::TestCase
    def test_challenge_33_larger_numbers
      # approx 1500 bits
      p = "0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74"\
          "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374f"\
          "e1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee38"\
          "6bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48"\
          "361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed52907"\
          "7096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff".hex

      g = 3

      a    = rand(p)         # alice private
      puba = g.pow(a, p)     # alice public

      b    = rand(p)         # bob private
      pubb = g.pow(b, p)     # bob public

      s1   = puba.pow(b, p)  # bob calculates S
      s2   = pubb.pow(a, p)  # alice calculates S

      assert_equal s1, s2    # they are equal
    end

    def test_challenge_33_smaller_numbers
      p    = 37
      g    = 5

      a    = rand(p)
      puba = (g ** a) % p

      b    = rand(p)
      pubb = (g ** b) % p

      s1   = (pubb ** a) % p
      s2   = (puba ** b) % p

      assert_equal s1, s2
    end
  end
end
