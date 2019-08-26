# https://cryptopals.com/sets/4/challenges/31
# https://cryptopals.com/sets/4/challenges/32
require_relative "../test_helper"

require "sinatra/base"
require "httparty"

module Set4
  KEY = OpenSSL::Random.random_bytes(16).unpack("H*")[0]

  # using puma here...
  class App < Sinatra::Base
    configure do
      set port: 5000
    end

    def _insecure_compare?(ours, theirs)
      ours.
        bytes.
        zip(theirs.bytes).
        all? do |l, r|
          sleep 0.005

          l == r
        end
    end

    get "/" do
      value  = params["file"]
      ours   = HMAC::SHA1.exec(KEY.dup, value)
      theirs = params["signature"]

      if _insecure_compare?(ours, theirs)
        status 200
      else
        status 500
      end
    end

    # just to make testing easier...
    get "/target" do
      value  = params["file"]
      ours   = HMAC::SHA1.exec(KEY.dup, value)

      ours
    end
  end

  class Challenge31Test < Test::Unit::TestCase
    def _get(file, signature)
      HTTParty.get(
        "http://localhost:5000", query: { file: file, signature: signature }
      )
    end

    def _run_challenge_31
      start    = Time.now
      universe = %w(a b c d e f 0 1 2 3 4 5 6 7 8 9)
      filename = "foo"
      server   = fork { App.run! }

      sleep 1

      # just to make testing easier...
      target   =
        HTTParty.get(
          "http://localhost:5000/target", query: { file: filename }
        ).bytes.pack("C*")

      # just to warm up the server
      _get(filename, universe[0])

      valid_mac =
        (0...40).reduce([]) do |acc, i|
          if i < 39
            results = Hash.new { |h, k| h[k] = [] }

            # this is sort of brutal, but it seems to work...
            30.times.reduce(results) do |r, _|
              universe.each do |char|
                t = Time.now

                _get(filename, acc.join + char)
                results[char] << Time.now - t
              end
            end

            key_value =
              results.max_by do |_char, times|
                times.reduce(:+) / times.length.to_f
              end.first

            puts "key value found: #{acc.join}#{key_value} "\
                 "(idx: #{i}) [actual: #{target}]"
          else
            key_value =
              universe.detect do |char|
                response =_get(filename, acc.join + char)

                response.code.to_i == 200
              end
          end

          acc <<  key_value

          if !target.include?(acc.join)
            raise "failed." # a retry would probably be nicer...
          end

          acc
        end

      valid_mac = valid_mac.compact.join

      assert_equal valid_mac, target

      Process.kill(:HUP, server)
      puts "Took #{start - Time.now} seconds."
    end

    # uncomment to run this; takes about 40+ minutes otherwise
    def test_challenge_31
      # _run_challenge_31
    end

    def test_hmac
      mac1  = OpenSSL::HMAC.hexdigest("SHA1", "A" * 64, "some-data")
      mac2  = HMAC::SHA1.exec("A" * 64, "some-data")

      assert_equal mac1, mac2
    end
  end
end
