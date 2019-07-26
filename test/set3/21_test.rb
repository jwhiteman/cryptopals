# https://cryptopals.com/sets/3/challenges/21
#
# https://en.wikipedia.org/wiki/Mersenne_Twister
#
require_relative "../test_helper"

module Set3
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
