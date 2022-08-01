# frozen_string_literal: true
require 'colorize'

# All stats for single IP is here
class IPStats
  DB = File.open('./miner/vendors.txt').read.downcase.lines.map(&:chomp).freeze
  attr_accessor :pkt_count, :macs, :domains, :hostnames, :open_ports

  def initialize(ip)
    @ip = ip
    @macs = Set.new
    @domains = Set.new
    @hostnames = Set.new
    @open_ports = Set.new
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
    @open_ports = @open_ports.to_a.sort

    top_line = [
      @ip.green,
      @hostnames.join('; ').yellow,
      "⇅#{@pkt_count}".blue
    ]

    stats = {
      'Ports': @open_ports.join('; '),
      'Domains': @domains.join('; '),
    }

    stat = stats.filter_map do |k, v| 
      "#{"#{k}:".yellow} #{v}" unless v.empty?
    end.join("\n")

    <<~STATS.strip
      #{top_line.reject(&:empty?).join(' ')}
      #{@macs.map{|mac| "• #{mac} #{get_vendor(mac).yellow}"}.join("\n")}

      #{stat}
    STATS
  end

  def get_vendor(mac)
    mac = mac.to_s.gsub(':', '')
    DB.find do |line|
      mac.start_with? line.split.first
    end.to_s.split(' ', 2).last || 'unknown'
  end
end
