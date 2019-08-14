# https://cryptopals.com/sets/4/challenges/28
require_relative "../test_helper"

module Set4
  class Challenge28Test < Test::Unit::TestCase
    KEY = OpenSSL::Random.random_bytes(16).unpack("H*")[0]

    def _f1(msg)
      SHA1.exec(KEY + msg)
    end

    def _valid?(msg, digest)
      _f1(msg) == digest
    end

    def test_challenge_28
      expected = OpenSSL::Digest::SHA1.hexdigest("Cryptopals!")
      actual   = SHA1.exec("Cryptopals!")

      assert_equal expected, actual

      msg       = "hello, world"
      digest    = _f1(msg)

      assert _valid?(msg, digest)

      digest[2] = (digest[2].ord ^ 1).chr # alter a bit

      refute _valid?(msg, digest)
    end
  end
end
