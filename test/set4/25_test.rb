# https://cryptopals.com/sets/4/challenges/25
require_relative "../test_helper"

module Set4
  module Challenge25
    KEY   = OpenSSL::Random.random_bytes(16).freeze
    NONCE = rand(2 ** 64)

    # Q: 64-bit unsigned, native endian (uint64_t)
    def ctr(text, key, nonce)
      text.
        bytes.
        each_slice(16).
        map.
        with_index do |block, block_index|
          keystream = _ecb_encrypt([nonce, block_index].pack("QQ"), key)

          block.map.with_index do |byte, byte_index|
            byte ^ keystream[byte_index].ord
          end
        end.flatten.pack("C*")
    end

    def _ecb_encrypt(p1, key)
      aes         = OpenSSL::Cipher.new("AES-128-ECB")
      aes.encrypt
      aes.key     = key
      aes.padding = 0

      aes.update(p1) + aes.final
    end

    def _keystream_bytes(key, nonce, counter)
      _ecb_encrypt([nonce, counter].pack("QQ"), key).bytes
    end

    BLOCKSIZE = 16
    def _edit(ciphertext, key, nonce, offset, newtext)
      counter = offset / BLOCKSIZE
      idx     = counter % BLOCKSIZE

      kbytes  = _keystream_bytes(key, nonce, counter)
      kbytes  = kbytes[idx..-1] # throw away bytes before the index
      counter = counter + 1

      newciphertext =
        newtext.
        bytes.
        map do |byte|
          if kbytes.empty?
            kbytes  = _keystream_bytes(key, nonce, counter)
            counter = counter + 1
          end

          byte ^ kbytes.shift
        end.pack("C*")

      ciphertext.dup.tap do |c|
        c[offset..(offset + newtext.length - 1)] = newciphertext
      end
    end

    def edit_oracle(ciphertext, offset, newtext)
      _edit(ciphertext, KEY, NONCE, offset, newtext)
    end
  end

  class Challenge25Test < Test::Unit::TestCase
    include Challenge25

    def test_challenge_25
      # ...copied from challenge-7:
      ciphertext = IO.read("test/fixtures/challenge-25-data.txt")
      ciphertext = ciphertext.split("\n").join.unpack("m0").first.chomp
      key        = "YELLOW SUBMARINE"
      cipher     = OpenSSL::Cipher.new("AES-128-ECB")
      cipher.key = key
      plaintext  = cipher.update(ciphertext) + cipher.final

      ciphertext = ctr(plaintext, KEY, NONCE)

      p2         = "A" * ciphertext.length
      c2         = edit_oracle(ciphertext, 0, p2)

      # we control p2 and c2, so we can get the original keystream back out.
      # whoops.

      discovered_keystream_bytes =
        p2.bytes.zip(c2.bytes).map { |l, r| l ^ r }

      # with the original keystream we can get back original plaintext back
      # by xor'ing it against the original ciphertext.
      discovered_plaintext =
        discovered_keystream_bytes.
        zip(ciphertext.bytes).
        map { |l, r| l ^ r }.
        pack("C*")

      assert_equal plaintext, discovered_plaintext
    end
  end
end
