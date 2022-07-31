#!/usr/bin/env ruby
# frozen_string_literal: true

require 'set'

require 'packetfu'

class IPStats
  DB = File.open('./vendors.txt').read.downcase.lines.map(&:chomp).freeze
  attr_accessor :pkt_count, :macs, :domains, :hostnames

  def initialize
    @macs = Set.new
    @domains = Set.new
    @hostnames = Set.new
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
    @macs = @macs.to_a.sort
    @domains = @domains.to_a.sort
    @hostnames = @hostnames.to_a.sort

    <<~STATS
      --------------------
      Packets: #{@pkt_count}
      MACs:    #{@macs.join('; ')}
      Vendors: #{vendors.join('; ')}
      Hostnames: #{@hostnames.join('; ')}
      Domains: #{@domains.join('; ')}
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
    @mac_hostname = {}
  end

  def mine
    @packets.each do |packet|
      next unless packet.proto.include? 'IP'

      %w[saddr daddr].each do |dest|
        mac = packet.send("eth_#{dest}").to_s
        ip = packet.send("ip_#{dest}")
        @mac_hostname[mac] = parse_dhcp_query(packet) if packet.is_a?(PacketFu::UDPPacket) && packet.udp_dst == 67
        next unless IPAddr.new(ip).private?

        @local_ips[ip].macs.add(mac)
        @local_ips[ip].new_packet

        if packet.is_a?(PacketFu::UDPPacket) && (packet.udp_dst == 53 && packet.payload[2..3].to_s == "\x01\x00")
          @local_ips[ip].domains.add(parse_dns_query(packet))
          next
        end
      end
    end

    @local_ips.each do |_ip, stats|
      stats.macs.each do |mac|
        stats.hostnames.add(@mac_hostname[mac])
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

  def parse_dns_query(packet)
    raw_domain = packet.payload[12..-1].to_s

    return nil if raw_domain[0].ord == 0

    fqdn = []
    offset = raw_domain[0].ord
    length = raw_domain[0..offset].length
    domain_name = raw_domain[(length - offset)..offset]

    while offset != 0
      fqdn << domain_name
      offset = raw_domain[length].ord
      domain_name = raw_domain[length + 1..length + offset]
      length = raw_domain[0..length + offset].length
    end

    fqdn.join('.')
  end

  def parse_dhcp_query(packet)
    hex = packet.payload[240..-1]

    i = 0
    options = []
    while i < hex.length
      opcode = hex[i]&.ord
      length = hex[i + 1]&.ord
      break unless length

      option = hex[i + 2, length]
      i += length + 2

      next unless [12, 60].include?(opcode)

      options << option
    end

    options.join(', ')
  end
end

miner = Miner.new(ARGV.first)
miner.mine
puts miner.stats
