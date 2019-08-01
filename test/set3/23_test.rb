# https://cryptopals.com/sets/3/challenges/23
require_relative "../test_helper"

module Set3
  module Challenge23
    L          = 18
    T          = 15
    C          = 0xEFC6_0000
    U          = 11
    S          = 7
    B          = 0x9D2C_5680

    def untemper(d)
      d = d ^ (d >> L)
      d = d ^ ((d << T) & C)
      d = _untemper_second(d)
      d = d ^ (d >> U) ^ (d >> 22)
    end

    def _untemper_second(d)
      s0  = d & (2 ** S) - 1
      acc = [s0]

      (1..4).each do |n|
        mask = ((2 ** S) - 1) << (n * S)

        sn = ((acc.last << S) & (B & mask)) ^ (d & mask)

        acc << sn
      end

      acc.reduce(:+)
    end
  end

  class Challenge23Test < Test::Unit::TestCase
    include Challenge23

    def test_untemper
      assert_equal untemper(3499211612), 2601187879
      assert_equal untemper(581869302), 3919438689
      assert_equal untemper(3890346734), 2270374771
    end

    def test_challenge_23
      seed        = rand(2 ** 32)
      prng        = MT19937.new(seed)

      clone       = MT19937.new(0)
      clone.mt    = 624.times.map { untemper(prng.rand) }
      clone.index = 624

      # test through a couple of cycles...
      (624 * 2).times do
        assert_equal clone.rand, prng.rand
      end
    end
  end
end
