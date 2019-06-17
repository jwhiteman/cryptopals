a = "1c0111001f010100061a024b53535009181c"
b = "686974207468652062756c6c277320657965"

def fixed_xor(a, b)
  (a.to_i(16) ^ b.to_i(16)).to_s(16)
end

puts fixed_xor(a, b)
