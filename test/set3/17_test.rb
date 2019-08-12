# https://cryptopals.com/sets/3/challenges/17
require_relative "../test_helper"

module Set3
  module Challenge17
    KEY = OpenSSL::Random.random_bytes(16).freeze
    IV  = OpenSSL::Random.random_bytes(16).freeze

    MSG = %w(
      MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
      MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
      MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
      MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
      MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
      MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
      MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
      MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
      MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
      MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93
    ).freeze

    # refactored, after-the-fact, to use technique stolen from technion
    def valid_pkcs7?(str)
      last = str[-1]

      if last.ord > 0 && last.ord <= 16
        padding_string = last * last.ord

        str[-16..-1] =~ /#{padding_string}$/
      else
        false
      end
    end

    # this isn't correct. TODO: read the pkcs7 spec, or something simplified.
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

    def cbc_encrypt(p, key, iv)
      p        = pkcs_7(p, 16)

      acc      = []
      previous = iv
      p.each_char.each_slice(16) do |pn|
        pn       = pn.join
        pn       = _xor(previous, pn)
        cn       = _ecb_encrypt(pn, key)
        previous = cn

        acc << cn
      end

      acc.join
    end

    def cbc_decrypt(c, key, iv)
      previous = iv
      acc      = []
      c.each_char.each_slice(16) do |cn|
        cn       = cn.join
        x        = _ecb_decrypt(cn, key)

        if block_given?
          yield x
        end

        p        = _xor(previous, x)
        previous = cn

        acc << p
      end

      acc.join
    end

    def _ecb_encrypt(p1, key)
      aes         = OpenSSL::Cipher.new("AES-128-ECB")
      aes.encrypt
      aes.key     = key
      aes.padding = 0

      aes.update(p1) + aes.final
    end

    def _ecb_decrypt(c1, key)
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

    def encrypted_message(msg)
      msg = Base64.strict_decode64(msg)
      $msg = msg
      p   = pkcs_7(msg, 16)
      $p  = p

      $c = cbc_encrypt(p, KEY, IV)
      $c
    end

    def has_valid_plaintext?(c)
      p = cbc_decrypt(c, KEY, IV)

      valid_pkcs7?(p)
    end

    class DiscoveredChar < Struct.new(:original, :successful_guess)
      def chr
        (original ^ successful_guess).chr
      end
    end

    BLOCKSIZE = 16
  end

  class Challenge17Test < Test::Unit::TestCase
    include Challenge17

    def test_challenge_17
      MSG.each do |m|
        msg = ""

        (IV.bytes + encrypted_message(m).bytes).
          each_slice(16).
          each_cons(2) do |block1, block2|
          discovered_chars = []
          15.downto(0) do |n|
            possible_answers = (0..255).select do |guess|
              c2     = block1 + block2
              c2[n]  = guess ^ (BLOCKSIZE - n)

              discovered_chars.each.with_index(1) do |dc, idx|
                c2[16 - idx] = dc.successful_guess ^ (BLOCKSIZE - n)
              end

              c2 = c2.pack("C*")

              has_valid_plaintext?(c2)
            end

            answer = possible_answers.
                     map { |pa| DiscoveredChar.new(block1[n], pa) }.
                     max_by { |dc| dc.chr }

            discovered_chars << answer
          end

          msg << discovered_chars.map(&:chr).reverse.join
        end

        assert msg.include?($msg)
      end
    end

    def test_scratch
      p1 = ("A" * 16) + ("B" * 14) + "Y" + "Z"
      c1 = cbc_encrypt(p1, KEY, IV)

      p2 = nil
      c2 = nil
      res = (0..255).detect do |guess|
        c2     = c1.clone
        c2     = c2.bytes
        c2[15] = guess ^ 1
        c2     = c2.pack("C*")

        p2 = cbc_decrypt(c2, KEY, IV)

        valid_pkcs7?(p2)
      end

      char = (c1[15].ord ^ res).chr

      assert_equal char, "Z"

      previous = res
      p2 = nil
      c2 = nil
      res = (0..255).detect do |guess|
        c2     = c1.clone
        c2     = c2.bytes
        c2[15] = previous ^ 2
        c2[14] = guess ^ 2
        c2     = c2.pack("C*")

        p2 = cbc_decrypt(c2, KEY, IV)

        valid_pkcs7?(p2)
      end

      char = (c1[14].ord ^ res).chr

      assert_equal char, "Y"
    end
  end
end
