# https://cryptopals.com/sets/1/challenges/1
hex = "49276d206b696c6c696e6720796f757220627261696e206c" \
      "696b65206120706f69736f6e6f7573206d757368726f6f6d"

original =
  hex.                              # take the hex string
    scan(/../).                     # chunk it into groups of 2-chars, because two hex-chars == a byte 16*16 (2 hex chars) = 2**8 (1 byte)
    reduce("") do |acc, hex_byte|   # let's decode the hex string
      acc << hex_byte.hex.chr       # ...each hex-byte can be converted into a number, and then we can look up its char
    end

puts original
puts [original].pack("m0")          # here we encode it to base64 using pack

require "base64"
puts Base64.strict_encode64(original)
