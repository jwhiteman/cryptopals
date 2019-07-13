$LOAD_PATH.unshift File.expand_path("../../lib", __FILE__)

require "test/unit"
require "openssl"
require "pry"
require "base64"

require "frequency"

include Frequency
