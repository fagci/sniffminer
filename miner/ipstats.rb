# frozen_string_literal: true

# All stats for single IP is here
class IPStats
  DB = File.open('./miner/vendors.txt').read.downcase.lines.map(&:chomp).freeze
  attr_accessor :pkt_count, :macs, :domains, :hostnames, :server_ports

  def initialize
    @macs = Set.new
    @domains = Set.new
    @hostnames = Set.new
    @server_ports = Set.new
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
    @server_ports = @server_ports.to_a.sort

    stats = {
      'Packets': @pkt_count.to_s,
      'MACs': @macs.join('; '),
      'Vendors': vendors.join('; '),
      'Hostnames': @hostnames.join('; '),
      'Domains': @domains.join('; '),
      'Server ports': @server_ports.join('; ')
    }
    largest_name_length = stats.keys.map(&:length).max + 1
    stats.filter_map { |k, v| "#{("#{k}:").ljust(largest_name_length)} #{v}" unless v.empty? }.join("\n")
  end

  def get_vendor(mac)
    mac = mac.to_s.gsub(':', '')
    DB.find do |line|
      mac.start_with? line.split.first
    end.to_s.split(' ', 2).last || 'n/a'
  end
end
