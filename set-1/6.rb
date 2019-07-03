require "open-uri"
require "base64"
require_relative "frequency"

def distance(s1, s2)
  b1 = s1.unpack("b*").first.scan(/./)
  b2 = s2.unpack("b*").first.scan(/./)

  b1.zip(b2).reduce(0) do |acc, (l, r)|
    acc += 1 if l.to_i != r.to_i
    acc
  end
end

def repeat_key_xor(key, plaintext)
  plaintext_bytes = plaintext.chomp.bytes
  key_bytes       = key.bytes

  plaintext_bytes.
    map.
    with_index do |pb, idx|
      encrypted_byte =
        pb ^ key_bytes[idx % key_bytes.length]
    end.pack("C*")
end

def possible_keylengths(ciphertext)
  (2..40).map do |keylength|
    result =
      ciphertext.
      each_char.
      each_slice(keylength).
      with_index.
      reduce({ distances: [] }) do |acc, (slice, idx)|
        slice = slice.join

        if idx == 0
          acc[:previous] = slice
        elsif idx > 10
          break acc
        elsif slice.length < keylength
          break acc
        else
          normalized_distance = 
            distance(acc[:previous], slice) / slice.length.to_f

          acc[:distances] << normalized_distance
          acc[:previous] = slice
        end

        acc
      end

    avg_distance =
      result[:distances].reduce(&:+) / result[:distances].length.to_f

    [avg_distance, keylength]
  end.sort
end

def possible_key(keysize, ciphertext)
  blocks =
    ciphertext[0...keysize**2].
    each_char.
    each_slice(keysize).
    to_a.
    transpose

  blocks.map do |block|
    results =
      SINGLE_BYTE_KEYS.map do |possible_key|
        h1 = block
        h2 = Array.new(h1.length) { possible_key }

        possible_plaintext =
          h1.zip(h2).map { |l, r| l.bytes.first ^ r }.pack("C*")

        [
          frequency_match_score(possible_plaintext),
          possible_key.chr,
          possible_plaintext
        ]
      end

    results.sort.last[1]
  end.join
end

open("https://cryptopals.com/static/challenge-data/6.txt") do |f|
  ciphertext = f.read
  ciphertext = ciphertext.lines.map(&:chomp).join.unpack("m0")[0]
  keylength  = possible_keylengths(ciphertext)[0].last
  key        = possible_key(keylength, ciphertext)
  plaintext  = repeat_key_xor(key, ciphertext)

  puts "KEY: #{key}"
  puts "PLAINTEXT:"
  puts plaintext
end
