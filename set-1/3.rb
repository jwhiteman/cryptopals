# https://cryptopals.com/sets/1/challenges/3
require "pry"
require_relative "frequency"

# this is our cipher text. it has been encrypted w/ a single char xor.
c1 = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

results =
  SINGLE_BYTE_KEYS.map do |c| # we'll iterate over 0-256 to look for the char
    h1 = c1.scan(/../) # take c1 and chunk it into bytes

    # a 'single char xor' still needs to be the same length as the plaintext
    # (which is the same length as the ciphertext
    # so, we'll create the single-char key that's the repeated byte
    h2 = Array.new(h1.length) { c }

    # we'll zip the two together, make sure that each "byte" is XOR'd with
    # the corresponding byte and then pack it back into a string, which represents
    # a possible plaintext
    p1 = h1.zip(h2).map { |l, r| l.hex ^ r }.pack("C*")

    # return the score of the plaintext, the plaintext, and the char
    [frequency_match_score(p1), p1, c.chr]
  end

puts results.sort.last
