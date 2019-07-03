# https://cryptopals.com/sets/1/challenges/5
# a little help from: https://is.gd/oGyqxO
require "pry"

plaintext = <<~PLAINTEXT
Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal
PLAINTEXT

key = "ICE"

def repeat_key_xor(key, plaintext)
  plaintext_bytes = plaintext.chomp.bytes
  key_bytes       = key.bytes

  plaintext_bytes.
    map.
    with_index do |pb, idx|
      encrypted_byte =
        pb ^ key_bytes[idx % key_bytes.length]

      sprintf("%02X", encrypted_byte)
    end.join
end

puts repeat_key_xor(key, plaintext)
