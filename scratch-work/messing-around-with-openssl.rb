<<~CMDS
openssl enc -aes-128-ecb -K 59454c4c4f57205355424d4152494e45 -nopad | xxd -p
openssl enc -aes-128-cbc -K 59454c4c4f57205355424d4152494e45 -iv 0 -nopad | xxd -p

printf aaaabbbbccccdddd | openssl enc -aes-128-ecb -K 59454c4c4f57205355424d4152494e45 -nopad -base64
CMDS

require "openssl"
key = "YELLOW SUBMARINE"
p1  = "aaaabbbbccccdddd"
aes = OpenSSL::Cipher.new("AES-128-ECB")
aes.encrypt
aes.key = key
aes.padding = 0

c1 = aes.update(p1)
c2 = aes.final
[c1].pack("m0")

def _ebc_encrypt(p1, key)
  aes         = OpenSSL::Cipher.new("AES-128-ECB")
  aes.encrypt
  aes.key     = key
  aes.padding = 0

  aes.update(p1) + aes.final
end

aes = OpenSSL::Cipher.new("AES-128-ECB")
aes.decrypt
aes.key = "YELLOW SUBMARINE"

puts aes.update(c1)

<<~CMD
# iv is "DOLLA DOLLA BILL"
# key is "YELLOW SUBMARINE"
openssl enc -aes-128-cbc -K 59454c4c4f57205355424d4152494e45 -iv 444F4C4C4120444F4C4C412042494C4C  | xxd -p
aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbcccccccccccccccc

chex = "681efa323b9c8c760482f9275f322db65d914256a91068912e7f6dec7fe73c0ae21af50e35224d94fe2aa827f97fe2057baf957b544d65a26b571666d6bd9ae1"

craw = chex.scan(/../).map(&:hex).pack("C*")

require "openssl"
aes = OpenSSL::Cipher.new("AES-128-CBC")
aes.decrypt
aes.key = "YELLOW SUBMARINE"
aes.iv = "DOLLA DOLLA BILL"
puts aes.update(craw) + aes.final

cbytes1 = craw.each_char.each_slice(16).map { |block| block.join.bytes }

cbytes2        = Marshal.load(Marshal.dump(cbytes1))
cbytes2[0][0] = cbytes1[0][0].succ

craw2          = cbytes2.flatten.pack("C*")

require "openssl"
aes = OpenSSL::Cipher.new("AES-128-CBC")
aes.decrypt
aes.key = "YELLOW SUBMARINE"
aes.iv = "DOLLA DOLLA BILL"
puts aes.update(craw2) + aes.final
CMD

# moar
<<~CMD
openssl enc -aes-128-cbc -K 59454c4c4f57205355424d4152494e45 -iv 444F4C4C4120444F4C4C412042494C4C -out dikhead.enc
aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbcccccccccccccccc
openssl enc -aes-128-cbc -d -K 59454c4c4f57205355424d4152494e45 -iv 444F4C4C4120444F4C4C412042494C4C -in dikhead.enc

craw = IO.read("dikhead.enc")

cbytes1 = craw.each_char.each_slice(16).map { |block| block.join.bytes }

cbytes2        = Marshal.load(Marshal.dump(cbytes1))
cbytes2[0][3]  = cbytes1[0][3].succ

craw2          = cbytes2.flatten.pack("C*")

File.open("dikhead2.enc", "w+") { |f| f << craw2 }

openssl enc -aes-128-cbc -d -K 59454c4c4f57205355424d4152494e45 -iv 444F4C4C4120444F4C4C412042494C4C -in dikhead.enc
CMD