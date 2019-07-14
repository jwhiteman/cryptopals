# https://cryptopals.com/sets/2/challenges/12
require_relative "../test_helper"

module Set2
  module Challenge12
    UNKNOWN_STRING =
      "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"\
      "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"\
      "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"\
      "YnkK".freeze

    KEY = OpenSSL::Random.random_bytes(16).freeze

    def encryption_oracle(p)
      p = p + Base64.strict_decode64(UNKNOWN_STRING)
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

    def ecb_or_cbc(c)
      acc = Hash.new { 0 }

      c.each_char.each_slice(16) do |slice|
        acc[slice] += 1
      end

      if acc.values.any? { |v| v > 1 }
        "ECB"
      else
        "CBC"
      end
    end
  end

  class Challenge12Test < Test::Unit::TestCase
    include Challenge12

    def test_challenge_12
      # 1. Discover the block size: keep incrementing the length of
      # the given plaintext until the ciphertext output jumps to the
      # next block size. the length of the jump is the block size.

      before = encryption_oracle("AAAAAA").length
      after  = encryption_oracle("AAAAAAA").length

      assert_equal after-before, 16

      # 2. Test for ECB
      mode   = ecb_or_cbc(encryption_oracle("A" * 32))
      assert_equal mode, "ECB"

      # 3. Decrypt the message
      numblocks = encryption_oracle("").length / 16

      # How this stupid thing works:
      #
      # 1. figure out many blocks long the unknown-text is, after padding.
      #
      # 2. for this explanation, assume 4-byte blocks.
      # let's say the uknown text looks like this (0's represent padding):
      #
      # |A B C D|E F 0 0|
      #
      # In this exercise, we can insert text at the beginning in such a way
      # that we can isolate a single byte of unknown text in a single block
      # with every other character being chars that we control (X's represent
      # chars that we control):
      #
      # |X X X A|B C D E|F 0 0 0|
      #
      # So that first block is something we can brute force. Assuming the
      # unknown text is ascii, then there are only 256 possibilities. Let's
      # save the first block above in a variable (let's say real_block_1).
      # Then let's feed the oracle all 256 possibilities of the form
      # `oracle("XXX#{byte}")`. In each iteration, we'll take the first
      # block and match it against `real_block_1`. When we find a match,
      # then we know that `byte.chr` is the the first character of the unknown
      # text.
      #
      # |X X A B|C D E F| => save first block again
      #
      # Iterate through the 256 ascii bytes: `oracle("XXA#{byte}")`, looking
      # at the resulting first block and trying to find a match against the
      # saved block above.
      #
      # Eventually we'll get to the end of the first block:
      #
      # |A B C D|E F 0 0|. D is still unknown. Save the first block
      #
      # Iterate through (0..255).each { |byte| oracle("ABC#{byte}") }, scanning
      # the first block in each, and comparing to the saved block above.
      #
      # Now we've got the first block, but need to move on to the subsequent
      # blocks (if there are any).
      #
      # |X X X A|B C D E|F 0 0 0|. E is unknown. Save the first TWO blocks now.
      #
      # `(0..255).each { |byte| oracle("XXXABCD#{byte}") }`. Now scan the first
      # two bytes of each iteration and look for a match on the saved two-block
      # variable above.
      #
      # In this way you can get each char of the unknown text.
      #
      # I'm guessing this is overly complicated and that there is a 1 liner
      # that will do the whole thing in a better way. But you gotta start
      # somewhere.

      previous_blocks = []
      (1..numblocks).each do |m|
        acc = []
        15.downto(0).each do |n|
          block = encryption_oracle("A" * n)[0..((m * 16) - 1)]

          char = (0..255).detect do |byte|
            p = [
                  ("A" * n),
                  previous_blocks,
                  acc,
                  byte.chr
                ].flatten.join

            encryption_oracle(p)[0..((m * 16) - 1)] == block
          end

          if char
            acc << char.chr
          else
            acc
          end
        end

        previous_blocks << acc
      end

      unknown_message = previous_blocks.flatten.join

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
