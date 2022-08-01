#!/usr/bin/env ruby
# frozen_string_literal: true

require 'set'
require 'packetfu'
require_relative 'ipstats'

# Collects infos about hosts from pcap file
class Miner
  def initialize
    @local_ips = Hash.new { |h, k| h[k] = IPStats.new }
    @mac_hostname = {}
  end

  def feed_multiple(files)
    files.each { |file| feed(file) }
  end

  def feed(file)
    PacketFu::PcapFile.read_packets(file).each do |packet|
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
  end

  def stats
    @local_ips.each do |_ip, stats|
      stats.macs.each do |mac|
        stats.hostnames.add(@mac_hostname[mac])
      end
    end
    @local_ips.sort.map do |ip, stats|
      <<~STATS
        #{ip}
        #{stats}
      STATS
    end
  end

  def parse_dns_query(packet)
    raw_domain = packet.payload[12..].to_s

    return nil if raw_domain[0].ord.zero?

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
    hex = packet.payload[240..]

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
