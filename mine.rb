#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative 'miner/miner'

puts 'Loading...'

miner = Miner.new
miner.feed(*ARGV)

puts ''

puts miner.stats
