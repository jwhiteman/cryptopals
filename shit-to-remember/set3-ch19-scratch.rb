# ks[n]  = c[suspiciously-popular-byte] XOR "e"
# c[spb] = ks[n] XOR "e"

suspiciously_popular_byte = e2.last.first

%w(E T A O I N S H R L D U e t a o i n s h r l d u).map do |guess|
  fixed_xor(bytes_at(b1, 2).join, (suspiciously_popular_byte.ord ^ guess.ord))
end


(0..256).map { |n| [n, fixed_xor(bytes_at(b1, 2).join, (derp.ord ^ n))] }


# setup: we'll take the most popular ciphertext byte, guess what letter it is,
# use that to derive a guess at the keystream byte, then "decrypt" the whole
# index cohort to see if it makes sense...
%w(A).map do |guess|
  [
    guess,
    fixed_xor(bytes_at(b1, 0).join, (e0.last.first.ord ^ guess.ord))
  ]
end

%w(o i h).map do |guess|
  [
    guess,
    fixed_xor(bytes_at(b1, 1).join, (e1.last.first.ord ^ guess.ord))
  ]
end

%w(E T A O I N S H R L D U e t a o i n s h r l d u).map do |guess|
  [
    guess,
    fixed_xor(bytes_at(b1, 2).join, (e2.last.first.ord ^ guess.ord))
  ]
end
