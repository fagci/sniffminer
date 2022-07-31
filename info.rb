#!/usr/bin/env ruby
# frozen_string_literal: true

require 'set'

require 'packetfu'

class IPStats
  DB = File.open('./vendors.txt').read.downcase.lines.map(&:chomp).freeze
  attr_accessor :pkt_count, :macs

  def initialize
    @macs = Set.new
    @pkt_count = 0
  end

  def new_packet
    @pkt_count += 1
  end

  def vendors
    @macs.map do |mac|
      get_vendor(mac)
    end
  end

  def to_s
    <<~STATS
      --------------------
      Packets: #{@pkt_count}
      MACs:    #{@macs.to_a.join('; ')}
      Vendors: #{vendors.join('; ')}
    STATS
  end

  def get_vendor(mac)
    mac = mac.to_s.gsub(':', '')
    DB.find do |line|
      mac.start_with? line.split.first
    end.to_s.split(' ', 2).last || 'n/a'
  end
end

class Miner
  def initialize(file)
    @packets = PacketFu::PcapFile.read_packets(file)
    @local_ips = Hash.new { |h, k| h[k] = IPStats.new }
  end

  def mine
    @packets.each do |packet|
      next unless packet.proto.include? 'IP'

      %w[saddr daddr].each do |dest|
        ip = packet.send("ip_#{dest}")
        next unless IPAddr.new(ip).private?

        mac = packet.send("eth_#{dest}")
        @local_ips[ip].macs.add(mac)
        @local_ips[ip].new_packet
      end
    end
  end

  def stats
    @local_ips.sort.map do |ip, stats|
      <<~STATS
        #{ip}
        #{stats}
      STATS
    end
  end
end

miner = Miner.new(ARGV.first)
miner.mine
puts miner.stats
