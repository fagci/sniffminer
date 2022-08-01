# frozen_string_literal: true

require 'packetfu'

module PacketFu
  class Packet
    def host_from_dns_query
      raw_domain = payload[12..].to_s

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

    def hostname_from_dhcp_query
      hex = payload[240..]

      i = 0
      options = []
      while i < hex.length
        opcode = hex[i]&.ord
        length = hex[i + 1]&.ord
        break unless length

        option = hex[i + 2, length]
        i += length + 2

        next unless opcode == 12

        options << option
        break
      end

      options.join(', ')
    end
  end
end
