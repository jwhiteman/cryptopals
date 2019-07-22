# https://cryptopals.com/sets/3/challenges/19
#
# https://en.wikipedia.org/wiki/Bigram
# https://en.wikipedia.org/wiki/Trigram
# https://www.coursera.org/learn/crypto/lecture/xAJaD/history-of-cryptography
#
require_relative "../test_helper"

module Set3
  module Challenge19
    KEY   = OpenSSL::Random.random_bytes(16).freeze
    NONCE = 0

    MSGS = %w(
      SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==
      Q29taW5nIHdpdGggdml2aWQgZmFjZXM=
      RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==
      RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=
      SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk
      T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
      T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=
      UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
      QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=
      T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl
      VG8gcGxlYXNlIGEgY29tcGFuaW9u
      QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==
      QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=
      QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==
      QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=
      QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=
      VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==
      SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==
      SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==
      VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==
      V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==
      V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==
      U2hlIHJvZGUgdG8gaGFycmllcnM/
      VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=
      QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=
      VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=
      V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=
      SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==
      U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==
      U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=
      VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==
      QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu
      SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=
      VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs
      WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=
      SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0
      SW4gdGhlIGNhc3VhbCBjb21lZHk7
      SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=
      VHJhbnNmb3JtZWQgdXR0ZXJseTo=
      QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=
    ).freeze

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
      acc = Hash.new { |h, k| h[k] = 0 }

      array.reduce(acc) do |acc, e|
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

  class Challenge19Test < Test::Unit::TestCase
    include Challenge19

    def test_challenge_19
      ciphertexts =
        MSGS.
        map do |msg|
          msg = Base64.strict_decode64(msg)

          ctr(msg, KEY, NONCE)
        end

      b1 = ciphertexts.map { |c| c[0..15] }

      e0 = counts(bytes_at(b1, 0))
      e1 = counts(bytes_at(b1, 1))
      e2 = counts(bytes_at(b1, 2))

      # c[n]  = p[n] XOR ks[n]
      # c[n]  = "e"  XOR ks[n]
      #
      # ks[n] = c[suspiciously-popular-byte] XOR "e"
    end
  end
end
