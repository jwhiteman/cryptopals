# https://cryptopals.com/sets/3/challenges/24
require_relative "../test_helper"

module Set3
  class StreamCipher
    attr_reader :seed
    attr_reader :index
    attr_reader :prng
    attr_reader :random_value

    def self.crypt(text, seed)
      new(seed).crypt(text)
    end

    def initialize(seed)
      @seed  = seed
      @prng  = MT19937.new(seed)
      @index = 0
    end

    def crypt(text)
      text.
        bytes.
        map do |byte|
          byte ^ keystream_byte
        end.pack("C*")
    end

    def keystream_byte
      idx  = index % 4
      mask = ((2 ** 8) - 1) << (8 * idx)

      @random_value = prng.rand if (idx).zero?
      @index += 1
      # puts sprintf("%032b", @random_value) 

      result = (random_value & mask) >> (8 * idx)
      # puts sprintf("%08b", result)

      result
    end
  end

  module CrackSeed
    extend self

    def exec(ciphertext, known_plaintext, seeds)
      seeds.detect do |seed|
        result =
          StreamCipher.crypt(ciphertext, seed)

        result.include?(known_plaintext)
      end
    end
  end

  class Challenge24Test < Test::Unit::TestCase
    def test_stream_cipher
      seed = rand(2 ** 16)
      msg  = "hello, world"
      c    = StreamCipher.crypt(msg, seed)
      p    = StreamCipher.crypt(c, seed)

      assert_equal p, msg
    end

    def test_challenge_24_part_1
      seed = rand(2 ** 8) # reducing to 8-bit seed, just for speed
      pref = OpenSSL::Random.random_bytes(rand(10) + 1)
      kp   = "A" * 14 # known-plaintext
      msg  = pref + kp
      c    = StreamCipher.crypt(msg, seed)

      assert_equal seed, CrackSeed.exec(c, kp, 0..2**8)
    end

    def test_challenge_24_part_2
      seed        = Time.now.to_i
      reset_token = StreamCipher.crypt("{user: 42; reset: true}", seed)

      now         = Time.now.to_i
      assert_equal seed, CrackSeed.exec(reset_token, "42", ((now-10)..now))
    end
  end
end
