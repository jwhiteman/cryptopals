# https://cryptopals.com/sets/2/challenges/14
require_relative "../test_helper"

module Set2
  module Challenge14
    UNKNOWN_STRING =
      "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"\
      "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"\
      "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"\
      "YnkK".freeze

    KEY = OpenSSL::Random.random_bytes(16).freeze

    PREFIX = OpenSSL::Random.random_bytes(rand(21) + 3).freeze

    def encryption_oracle(p)
      p = PREFIX + p + Base64.strict_decode64(UNKNOWN_STRING)
      p = pkcs_7(p, 16)

      ebc_encrypt(p, KEY)
    end

    def pkcs_7(block, blocksize)
      padding_amount =
        if block.length < blocksize
          blocksize - block.length
        elsif block.length % blocksize == 0
          0
        else
          n = block.length % blocksize

          blocksize - n
        end

      (block.bytes + ([padding_amount] * padding_amount)).pack("C*")
    end

    def ebc_encrypt(p1, key)
      aes         = OpenSSL::Cipher.new("AES-128-ECB")
      aes.encrypt
      aes.key     = key
      aes.padding = 0

      aes.update(p1) + aes.final
    end

    def ebc_decrypt(c1, key)
      aes         = OpenSSL::Cipher.new("AES-128-ECB")
      aes.decrypt
      aes.key     = key
      aes.padding = 0

      aes.update(c1) + aes.final
    end

    def _xor(cn, pn)
      cn  = cn.bytes
      pn  = pn.bytes
      acc = []

      cn.length.times do |idx|
        acc << (cn.at(idx) ^ pn.at(idx))
      end

      acc.pack("C*")
    end
  end

  class Challenge14Test < Test::Unit::TestCase
    include Challenge14

    def test_challenge14
      # find the exact point where 2 identical blocks appear:
      correction     = nil
      blocks_to_skip = nil

      # We'll assume that the prefix is anywhere between 0 and 40 bytes
      (0..40).each do |n|
        oracle_output    = encryption_oracle(("X" * 32) + ("X" * n))
        resulting_blocks = oracle_output.each_char.each_slice(16).to_a

        if resulting_blocks.uniq.length < resulting_blocks.length
          correction = n
          seen       = Hash.new { 0 }

          resulting_blocks.each_with_index do |block, idx|
            idx          = idx + 1 # let's start at index 1 instead of 0
            seen[block] += 1

            if seen[block] > 1
              # we've found our 2nd repeated block, so backtrack 2
              blocks_to_skip = idx - 2

              break
            end
          end

          break
        end
      end

      bytes_to_skip   = blocks_to_skip * 16
      previous_blocks = []
      unknown_message = catch(:done!) do
        (1..1/0.0).each do |m|
          acc = []
          15.downto(0).each do |n|
            padding = ("A" * correction) + ("A" * n)
            range   = (bytes_to_skip...(bytes_to_skip + (16 * m)))
            block   = encryption_oracle(padding)[range]

            char = (0..255).detect do |byte|
              p = [
                padding,
                previous_blocks,
                acc,
                byte.chr
              ].flatten.join

              encryption_oracle(p)[range] == block
            end

            if char
              acc << char.chr
            else
              throw :done!, [previous_blocks, acc].flatten.join
            end
          end

          previous_blocks << acc
        end
      end

      assert_equal(
        unknown_message.lines[0], "Rollin' in my 5.0\n"
      )

      assert_equal(
        unknown_message.lines[1], "With my rag-top down so my hair can blow\n"
      )

      assert_equal(
        unknown_message.lines[2],
        "The girlies on standby waving just to say hi\n"
      )

      assert_match(
        unknown_message.lines[3],
        "Did you stop? No, I just drove by\n"
      )
    end
  end
end
