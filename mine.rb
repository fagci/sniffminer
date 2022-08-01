#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative 'miner/miner'

miner = Miner.new
miner.feed_multiple(ARGV)
puts miner.stats
