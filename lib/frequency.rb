module Frequency
  VALID_BYTES      = ([32] + (65..90).to_a + (97..122).to_a).freeze
  SINGLE_BYTE_KEYS = (0..255).to_a.freeze
  FREQUENT         = ["e", "t", "a", "o", "i", "n", " "].freeze

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
end
