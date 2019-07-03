require "pry"

VALID_BYTES      = ([32] + (65..90).to_a + (97..122).to_a).freeze
SINGLE_BYTE_KEYS = (0..255).to_a.freeze
FREQUENT         = ["e", "t", "a", "o", "i", "n", " "].freeze

=begin
# winner should be 'u'
[1, "u", " y lbda"],
[2, "X", "\rT\rAOIL"],
[2, "x", "-t-aoil"]]

 # winner should be 'a'
[1, "E", "HI\x04\x04AHI"],
[1, "a", "lm  elm"],
[1, "e", "hi$$ahi"],
[2, "B", "ON\x03\x03FON"],
[2, "C", "NO\x02\x02GNO"],
[2, "b", "on##fon"],
[2, "c", "no\"\"gno"]]
=end

def frequency_match_score(plaintext)
  plaintext = plaintext.downcase

  frequency_score =
    plaintext.
    each_char.
    reduce(0) do |acc, char|
      acc = acc + 1 if FREQUENT.include?(char)

      acc
    end

  liability_score =
    plaintext.
    each_char.
    reduce({ score: 0 }) do |acc, char|
      byte = char.bytes.first

      if !VALID_BYTES.include?(byte)
        if acc[:has_existing_bad_bytes]
          acc[:score] -= 2
        else
          acc[:has_existing_bad_bytes] = true
          # acc[:score] -= 1
        end
      end

      acc
    end

  frequency_score + liability_score[:score]
end
