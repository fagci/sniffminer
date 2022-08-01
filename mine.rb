#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative 'miner/miner'

miner = Miner.new(ARGV.first)
miner.mine
puts miner.stats
