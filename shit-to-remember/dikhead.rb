# this doesn't work. why?
require "openssl"
require "pry"
craw = IO.read("dikhead.enc")

cbytes1 = craw.bytes.each_slice(16)
aes     = OpenSSL::Cipher.new("AES-128-CBC")
aes.decrypt
aes.key = "YELLOW SUBMARINE"
aes.iv  = "DOLLA DOLLA BILL"
c1      = cbytes1.to_a.flatten.pack("C*")
p1      = aes.update(c1) + aes.final
puts "1: #{p1}"

cbytes2 = cbytes1.take(2)
aes     = OpenSSL::Cipher.new("AES-128-CBC")
aes.decrypt
aes.key = "YELLOW SUBMARINE"
aes.iv  = "DOLLA DOLLA BILL"
c2      = cbytes2.to_a.flatten.pack("C*")
begin
  puts "2: #{aes.update(c2) + aes.final}"
rescue
  puts "2: failed decrypting the 2-block truncated cipher as-is"
end


(0..255).each do |guess|
  aes = OpenSSL::Cipher.new("AES-128-CBC")
  aes.decrypt
  aes.key = "YELLOW SUBMARINE"
  aes.iv  = "DOLLA DOLLA BILL"

  original = cbytes2[0][15]
  cbytes2[0][15] = (guess ^ 1)
  c3 = cbytes2.flatten.pack("C*")
  p3 = aes.update(c3) + aes.final

  byte = guess ^ original ^ 1
  puts "OK: I guess the last byte of the 2nd block is: #{byte.chr.inspect}"
rescue => e
end
