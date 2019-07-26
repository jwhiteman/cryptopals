# https://cryptopals.com/sets/3/challenges/22
require_relative "../test_helper"

module Set3
  class Challenge22Test < Test::Unit::TestCase
    def test_challenge_22
      index = Hash.new { |h, k| h[k] = [] }

      start = Time.now.to_i

      # we'll load up values for the next 20 minutes or so
      (start..(start + 1200)).each do |seed|
        prng = MT19937.new(seed)

        1000.times do
          index[prng.rand] << seed
        end
      end

      # curmudgeonly simulating the passage of time...
      used_seed = Time.now.to_i + rand(1000)

      prng = MT19937.new(used_seed)

      r1   = prng.rand
      rand(100).times { prng.rand } # miss a few values
      r2   = prng.rand
      rand(100).times { prng.rand } # miss a few more values
      r3   = prng.rand

      found_seed = (index[r1] & index[r2] & index[r3]).first

      assert_equal used_seed, found_seed
    end
  end
end
