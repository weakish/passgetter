# -*- encoding : utf-8 -*-
require_relative 'passgetter/version'
require 'openssl'
require 'digest'

module Passgetter
  module_function

  # Derive a key.
  #
  # @param pass [String] master passphrase in UTF-8
  # @param salt [String] usually domain names
  # @param kdf [Symbol] Key derivation function
  # @param options [Hash] options for KDF
  # @return [String] base16 form (padding with 0) of key if base_16 is true
  # @return [String] binary string of key if base_16 is false
  #
  # @example Derive a key using default options.
  #   derive_key('pass', 'example.com')
  #   #=> '34817086825b1b6bd4d841e9dee396eadbc0aa6fbc1dc05551294ad74d919e0a'
  #
  # @example Use scrypt.
  #   derive_key('pass', 'example.com', :scrypt)
  #   #=> 'e8214d68fd9a0ad533fa5b700854dc77d508fe4db6dc647115478332a72d3d83'
  #
  # @example Return binary key.
  #   derive_key('pass', 'example.com', :pbkdf2, {}, false)
  #   #=> "4\x81p\x86\x82[\ek\xD4\xD8A\xE9\xDE\xE3\x96\xEA\xDB\xC0\xAAo\xBC\x1D\xC0UQ)J\xD7M\x91\x9E\n"
  #   derive_key('pass', 'example.com', :scrypt, {n: 2**14}, false)
  #   #=> "X'\xCA\r~\x19\xF6G\xB5\\\xF7\x06\xD7\e\x8Ei\x16o\x10\xC8\ti\xFD$7Hj\x81_\x172("
  #
  # Default kdf is pbkdf2, since it does not require additional gems.
  def derive_key(pass, salt, kdf=:pbkdf2, options={}, base_16=true)
    if kdf == :pbkdf2
      iter = options[:iter] || 40000
      # Fall back to keylen since OpenSSL::PKCS5 uses keylen.
      key_len = options[:key_len] || options[:keylen] || 32
      digest = options[:digest] || OpenSSL::Digest::SHA1.new
      key = OpenSSL::PKCS5.pbkdf2_hmac(pass, salt, iter, key_len, digest)
    elsif kdf == :scrypt
      require 'scrypt'
      # key_len range: 16 bytes (128 bits) - 512 bytes (4096 bits)
      # Default to the default value of scrypt gem.
      key_len = options[:key_len] || 32
      # Default values from scrypt author's recommendation:
      # http://www.tarsnap.com/scrypt/scrypt-slides.pdf
      # General work factor, iteration count.
      n = options[:n] || 2**20
      # Blocksize in use for underlying hash;
      # fine-tunes the relative memory-cost.
      r = options[:r] || 8
      # Parallelization factor; fine-tunes the relative cpu-cost.
      p = options[:p] || 1
      key = SCrypt::Engine.scrypt(pass, salt, n, r, p, key_len)
    else
      raise NotImplementedError, "{kdf}.to_s is not implemented."
    end
    if base_16
      Digest.hexencode key
    else
      key
    end
  end

  # Convert key to BaseX.
  #
  # @param key [String] binary string
  # @param base [Fixnum] required
  #   64 is url safe base64, see
  #   "Base 64 Encoding with URL and Filename Safe Alphabet" in RFC 4648
  #   85 is Z85 (ZeroMQ Base-85), see
  #   http://rfc.zeromq.org/spec:32
  #   For base other than 64, 85 and 91, we first hexencode the binary string,
  #   then convert to the required base, and map against `[0-9a-zA-Z]`.
  # @param list [Array<String>] required if base is not 2-62, 64, 85, 91
  # @return [String]
  #   Note that base64 and base91 are encoded directly on the key string,
  #   while other bases will first convert the key string to number.
  #
  # @example generate passwords
  #   key = "X'\xCA\r~\x19\xF6G\xB5\\\xF7\x06\xD7\e\x8Ei\x16o\x10\xC8\ti\xFD$7Hj\x81_\x172("
  #   base_key(key, 10) # pin [0-9]
  #   #=> '39873832227375186443151239195760257905556277081737845106190724045279126303272'
  #   base_key(key, 36) # [0-9a-z]
  #   #=> '273jl05axr9r7pdeix720rj3fciuv0jhueyqp6dyia1sp7rs4o'
  #   base_key(key, 62) # [0-9a-zA-Z]
  #   #=> 'kU4nWuBVIG7RJY5qUu1GU8sJxj9GBGlXTYNdmHiUjIQ'
  #   base_key(key, 64) # url safe base64
  #   #=> 'WCfKDX4Z9ke1XPcG1xuOaRZvEMgJaf0kN0hqgV8XMig='
  #   base_key(key, 85) # Base85
  #   #=> 'ssql2EI}&HWoSCg/bG-:7h<=932ft-h+mXmuL+EC'
  #   base_key(key, 91) # Base91
  #   #=> '8Uho7}`n85(oj>3;!nc2L>W!&uR~j@jZ3J`;Uj@A'
  #   base63 = ('0'..'9').to_a + ('a'..'z').to_a + ('A'..'Z').to_a + ['_']
  #   base_key(key, 63, base63)
  #   #=> 'aGyKjKefXw0xAoRrntxDbDJ5dcWnH7t3AjM_Wlg7ewf'

  def base_key(key, base, list=[])

    # Convert key to BaseX via radix.
    # Usually you can use base_key instead.
    #
    # @param key [String] hex string
    # @param base [Fixnum]
    # @param list [Array<String>]
    # @return [String]
    base_key_via_radix = ->(list) do
      require 'radix'
      # Since we use `.b` on an Integer, the collision of String method
      # `.b` on Ruby 2.1 will not bite us. Bug report is at:
      # https://github.com/rubyworks/radix/issues/10
      Digest.hexencode(key).to_i(16).b(base).to_s(list)
    end

    # Ruby's to_s limits to 36.
    if base < 36
      Digest.hexencode(key).to_i(16).to_s(base)
    elsif base <= 62
      characters_map = ('0'..'9').to_a + ('a'..'z').to_a + ('A'..'Z').to_a
      characters_used = characters_map[0..(base - 1)]
      base_key_via_radix[characters_used]
    elsif base == 64
      require 'base64'
      Base64.urlsafe_encode64 key
    elsif base == 85
      require 'z85'
      Z85.encode key
    elsif base == 91
      require 'base91'
      Base91.encode key
    else
      base_key_via_radix[list]
    end
  end

  # Return words based on key.
  #
  # @param key [String] binary
  # @param wordlist_path [String] path to wordlist file
  #   One word per line.
  #   Default: wordlist from wamerican-insane (7.1-1) in Debian.
  #   We capitalized all words.
  # @return [String] words
  #
  # @example
  #   key = "X'\xCA\r~\x19\xF6G\xB5\\\xF7\x06\xD7\e\x8Ei\x16o\x10\xC8\ti\xFD$7Hj\x81_\x172("
  #   base_words(key)
  #   #=> %q(AAgrMouldmadeDipneumonousDebera'sPaisley'sThermosphericAmpherotokousTantalusTrantedTrichorrhexisRufisque'sSalpidae'sStinkyfootInvasiveness)
  def base_words(key, wordlist_path=File.expand_path('../../data/wordlist', __FILE__))
    open(wordlist_path) do |f|
      wordlist = f.to_a.map &:chomp
      base_key(key, wordlist.length, wordlist)
    end
  end
end
