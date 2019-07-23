# https://cryptopals.com/sets/3/challenges/20
require_relative "../test_helper"

module Set3
  module Challenge20
    KEY   = OpenSSL::Random.random_bytes(16).freeze
    NONCE = 0

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

    def counts(array)
      accumulator = Hash.new { |h, k| h[k] = 0 }

      array.reduce(accumulator) do |acc, e|
        acc[e] += 1

        acc
      end.sort_by { |k, v| v }
    end

    def bytes_at(array, n)
      array.map { |s| s[n] }
    end

    def fixed_xor(string, xor_byte)
      string.
        each_byte.
        map.
        with_index do |byte, idx|
          byte ^ xor_byte
        end.pack("C*")
    end
  end

  class Challenge20Test < Test::Unit::TestCase
    include Challenge20

    def test_challenge_20
      msgs  = IO.read("test/fixtures/challenge-20-data.txt")

      ciphertexts =
        msgs.
        lines.
        map do |msg|
          msg = Base64.strict_decode64(msg.chomp)

          ctr(msg, KEY, NONCE)
        end

      min_length = ciphertexts.map(&:length).min

      truncated_ciphertexts =
        ciphertexts.
        map do |c|
          c[0...min_length]
        end

      winners = 
        (0...min_length).
        map do |n|
          bytes_n  = bytes_at(truncated_ciphertexts, n).join

          (0..255).map do |keystream_byte_guess|
            pt = fixed_xor(bytes_n, keystream_byte_guess)

            # just sort of ad-hoc'd this until it came out right
            score =
              if pt =~ /[@~^]/ || pt =~ /[[:cntrl:]]/
                0
              else
                pt.scan(/[ETAOIN SHRLDU]/i).count
              end

            [score, pt]
          end.max
        end

      plaintexts =
        winners.
        map { |_score, text| text.split(//) }.
        transpose.
        map(&:join)

      assert_equal(
        plaintexts.last,
        "And we outta here / Yo, what happened to peace? / Pea"
      )
    end
  end
end
