# https://cryptopals.com/sets/1/challenges/4

require "pry"
require "open-uri"
require_relative "frequency"

open("https://cryptopals.com/static/challenge-data/4.txt") do |f|
  data = f.read

  results =
    data.
    lines.
    map.
    with_index do |possible_ciphertext, idx|
      possible_ciphertext.chomp!

      VALID_BYTES.map do |possible_key|
        h1 = possible_ciphertext.scan(/../)
        h2 = Array.new(h1.length) { possible_key }

        possible_plaintext =
          h1.zip(h2).map { |l, r| l.hex ^ r }.pack("C*")

        [
          frequency_match_score(possible_plaintext),
          possible_plaintext,
          possible_key.chr,
          possible_ciphertext,
          idx
        ]
      end
    end

  results =
    results.flatten(1).sort

  winner = results.last
  
  output =
    {
      score: winner[0],
      plaintext: winner[1],
      key: winner[2],
      ciphertext: winner[3],
      line_number: winner[4].succ
    }

  puts output.inspect
end
