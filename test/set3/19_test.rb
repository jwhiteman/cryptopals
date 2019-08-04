# https://cryptopals.com/sets/3/challenges/19
#
# https://en.wikipedia.org/wiki/Bigram
# https://en.wikipedia.org/wiki/Trigram
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

    class Key
      attr_reader :key

      def initialize
        @results = []
        @key     = []
      end

      def add(keystream_byte)
        key << keystream_byte
      end
    end

    def decrypt(ciphertexts, k)
      k = k.key

      ciphertexts.map do |c|
        c[0..k.length-1].
          bytes.
          zip(k).
          map do |l, r|
            l ^ r
          end.
          pack("C*")
      end
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

      k = Key.new

      k.add(ciphertexts[0][0].ord ^ "I".ord)
      k.add(ciphertexts[0][1].ord ^ " ".ord)
      k.add(ciphertexts[20][2].ord ^ "a".ord)
      k.add(ciphertexts[25][3].ord ^ "s".ord)
      k.add(ciphertexts[1][4].ord ^ "n".ord)
      k.add(ciphertexts[1][5].ord ^ "g".ord)
      k.add(ciphertexts[27][6].ord ^ "h".ord)
      k.add(ciphertexts[27][7].ord ^ "t".ord)
      k.add(ciphertexts[15][8].ord ^ "l".ord)
      k.add(ciphertexts[15][9].ord ^ "e".ord)
      k.add(ciphertexts[28][10].ord ^ "v".ord)
      k.add(ciphertexts[28][11].ord ^ "e".ord)
      k.add(ciphertexts[3][12].ord ^ "e".ord)
      k.add(ciphertexts[3][13].ord ^ "n".ord)
      k.add(ciphertexts[3][14].ord ^ "t".ord)
      k.add(ciphertexts[3][15].ord ^ "u".ord)
      k.add(ciphertexts[3][16].ord ^ "r".ord)
      k.add(ciphertexts[3][17].ord ^ "y".ord)
      k.add(ciphertexts[31][18].ord ^ "o".ord)
      k.add(ciphertexts[31][19].ord ^ "r".ord)
      k.add(ciphertexts[31][20].ord ^ "i".ord)
      k.add(ciphertexts[31][21].ord ^ "o".ord)
      k.add(ciphertexts[31][22].ord ^ "u".ord)
      k.add(ciphertexts[31][23].ord ^ "s".ord)
      k.add(ciphertexts[24][24].ord ^ "e".ord)
      k.add(ciphertexts[19][25].ord ^ "l".ord)
      k.add(ciphertexts[19][26].ord ^ "l".ord)
      k.add(ciphertexts[32][27].ord ^ "n".ord)
      k.add(ciphertexts[32][28].ord ^ "g".ord)
      k.add(ciphertexts[29][29].ord ^ "h".ord)
      k.add(ciphertexts[29][30].ord ^ "t".ord)
      k.add(ciphertexts[25][31].ord ^ "d".ord)
      k.add(ciphertexts[4][32].ord ^ "h".ord)
      k.add(ciphertexts[4][33].ord ^ "e".ord)
      k.add(ciphertexts[4][34].ord ^ "a".ord)
      k.add(ciphertexts[4][35].ord ^ "d".ord)
      k.add(ciphertexts[37][36].ord ^ "n".ord)
      k.add(ciphertexts[37][37].ord ^ ",".ord)

      results = decrypt(ciphertexts, k)

      MSGS.each_with_index do |msg, idx|
        msg = Base64.strict_decode64(msg)

        assert_equal msg, results[idx]
      end
    end
  end
end
