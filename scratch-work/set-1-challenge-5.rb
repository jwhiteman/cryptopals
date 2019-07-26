# lesson, if you're going to join hex strings, make sure
# that they all have equal width - e.g "b" is "0b", etc
# solution: use `sprintf("%02X", encrypted_byte)` for padding.

# from cryptopals
c1 =
  "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26" \
  "226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c69" \
  "2b20283165286326302e27282f"

# my broken output (missing 0 padding in some places)
c2 =
  "b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26" \
  "226324272765272a282b2f2043a652e2c652a3124333a653e2b202763c69" \
  "2b20283165286326302e27282f"

# finally when my output is correct
c3 = 
  "0B3637272A2B2E63622C2E69692A23693A2A3C6324202D623D63343C2A26" \
  "226324272765272A282B2F20430A652E2C652A3124333A653E2B2027630C69" \
  "2B20283165286326302E27282F"

key = "ICE"
key_bytes = key.bytes

p1 =
  c3.
    scan(/../).
    map.
    with_index do |hex, idx|
      hex.hex ^ key_bytes[idx % key_bytes.length]
    end.pack("C*")

puts p1
