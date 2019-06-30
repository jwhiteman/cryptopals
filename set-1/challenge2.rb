a = "1c0111001f010100061a024b53535009181c"
b = "686974207468652062756c6c277320657965"

def fixed_xor_cheating(a, b)
  (a.to_i(16) ^ b.to_i(16)).to_s(16)
end
puts fixed_xor_cheating(a, b)

def fixed_xor(a, b)
  h1 = a.scan(/../) # chunk each hex string into "bytes"
  h2 = b.scan(/../)

  # zip them together, so that each byte can be with its corresponding
  # byte in the other string.
  # convert each to a number (representing the bytes), and then XOR'ing
  # them together, then finally use pack to convert the array-of-number-bytes
  # into a series of unsigned chars (aka, the message)
  m = h1.zip(h2).map { |l, r| l.hex ^ r.hex }.pack("C*")

  # m
  # => "the kid don't play"

  # finally turn it back into hex
  # unpack, here, returns an array with a single element, so we grab it
  m.unpack("H*").first
end

puts fixed_xor(a, b)
