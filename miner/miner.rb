#!/usr/bin/env ruby
# frozen_string_literal: true

require 'set'
require 'packetfu'
require_relative 'packet'
require_relative 'ipstats'

# Collects infos about hosts from pcap file
class Miner
  def initialize
    @mac_hostname = {}
    @local_ips = Hash.new { |h, k| h[k] = IPStats.new(k) }
  end

  def feed(*files)
    files.each do |file|
      PacketFu::PcapFile.read_packets(file).each do |packet|
        process(packet) if packet.proto.include? 'IP'
      end
    end
  end

  def process(packet)
    gather_local_addresses(packet)
    extract_info(packet)
  end

  def gather_local_addresses(packet)
    %w[saddr daddr].each do |dest|
      mac = packet.send("eth_#{dest}").to_s
      ip = packet.send("ip_#{dest}")

      next unless IPAddr.new(ip).private?

      @local_ips[ip].macs.add(mac)
      @local_ips[ip].new_packet
    end
  end

  def extract_info(packet)
    case packet
    when PacketFu::UDPPacket
      # use MACs as key for DHCP request
      @mac_hostname[packet.eth_daddr] = packet.hostname_from_dhcp_query if packet.udp_dst == 67

      if packet.udp_dst == 53 && packet.payload[2..3].to_s == "\x01\x00"
        @local_ips[packet.ip_saddr].domains.add(packet.host_from_dns_query)
      end
    when PacketFu::TCPPacket
      # NOTE: alpha version of open ports detection
      if IPAddr.new(packet.ip_saddr).private? && packet.tcp_src <= 1024
        @local_ips[packet.ip_saddr].open_ports.add(packet.tcp_src)
      end
    end
  end

  def stats
    @local_ips.each do |_ip, stats|
      stats.macs.each do |mac|
        stats.hostnames.add(@mac_hostname[mac])
      end
    end

    @local_ips.sort.to_h.values.join("\n\n")
  end
end
