#!/usr/bin/ruby

require 'net/http'
require 'ruby-graphviz'
require 'cgi'

VOFR_LG_URL='https://vofr.net/lg/'
SPOTTY_LG_URL='http://127.0.0.1/lg/lg.cgi?query=bgp&protocol=IPv4&addr=&router=KTNRONSPVR01&nodesc=1'

AS_TXT='./as.txt'

class BGPPaths
  attr_reader :local_asn
  attr_reader :all_paths
  attr_reader :path_hops

  def initialize(bgp_output:, local_asn: nil)
    @all_paths = []
    @path_hops = []
    @local_asn = local_asn.to_s

    bgp_output.each_line do |line|
      if(asn = /local AS (\d+)/.match(line)) then
        @local_asn = asn[1]
      end
      if(pathdata = /(6\d{4}.*)$/.match(line) and !line.include? 'table version') then
        path = [@local_asn, pathdata[1].split(' ')[0..-2]].flatten
        next if path == [@local_asn]
        @all_paths << path
        (0..path.length-2).each do |idx|
          @path_hops << "#{path[idx]}-#{path[idx+1]}"
        end
      end

      @all_paths.uniq!
      @path_hops.uniq!
    end
  end
end

class ASDatabase
  attr_reader :ass

  def initialize
    @ass = {}
    File.read(AS_TXT).each_line do |line|
      next if /^\s*#|^\s*$/.match(line)
      as_data = /\s*(\d+)\s+(.*)/.match(line)
      @ass[as_data[1].to_i] = as_data[2]
    end
  end

  def [](asn)
    @ass[asn]
  end
end

def accessing_over_mesh(cgi)
  # check if the route back is via shadymesh, if so then show sensitive info
  return true unless cgi.remote_addr
  route_to_remote = `ip route get #{cgi.remote_addr}`
  return true unless route_info = /via\s+(\S+)/.match(route_to_remote)
  remote_gw = route_info[1]

  return true if remote_gw == '172.20.0.1' or !remote_gw;
  false
end

cgi = CGI.new

uri = URI(VOFR_LG_URL)
vofr_paths = Net::HTTP.get(uri)
current_node = :unknown
vofr_data = {east: '', west: ''}
vofr_paths.each_line do |line|
  if(line.start_with? '***US-WEST') then
    current_node = :west
    next
  elsif(line.start_with? '***US-EAST') then
    current_node = :east
    next
  elsif(line.include? '</pre>') then
    current_node = :unknown
    next
  end
  next unless current_node != :unknown
  vofr_data[current_node] += line
end

vofr_east_paths = BGPPaths.new(bgp_output: vofr_data[:east])
vofr_west_paths = BGPPaths.new(bgp_output: vofr_data[:west])

uri = URI(SPOTTY_LG_URL)
local_paths = BGPPaths.new(bgp_output: Net::HTTP.get(uri), local_asn: 64778)

all_path_hops = [vofr_east_paths.path_hops, vofr_west_paths.path_hops, local_paths.path_hops].flatten.uniq
asdb = ASDatabase.new

is_over_mesh = accessing_over_mesh(cgi)
is_over_mesh = false if cgi.params.keys.include? 'nonames'

graph = GraphViz.new(:G, :type => 'strict digraph')
all_path_hops.each do |path_hop|
  asns = path_hop.split('-')
  asns = path_hop.split('-').sort unless cgi.params.keys.include? 'directed'
  as_a_desc = "AS#{asns[0]}"
  as_a_desc += "\n#{asdb[asns[0].to_i]}" if asdb[asns[0].to_i] and is_over_mesh
  as_b_desc = "AS#{asns[1]}"
  as_b_desc += "\n#{asdb[asns[1].to_i]}" if asdb[asns[1].to_i] and is_over_mesh
  
  as_a = nil
  if(asns[0] == '64778')
    as_a = graph.add_nodes(as_a_desc, fillcolor: 'lightblue', style: 'filled')
  elsif(asns[0].to_i == vofr_east_paths.local_asn.to_i) then
    as_a = graph.add_nodes(as_a_desc, fillcolor: 'lightyellow', style: 'filled')
  elsif(asns[0].to_i == vofr_west_paths.local_asn.to_i) then
    as_a = graph.add_nodes(as_a_desc, fillcolor: 'lightyellow', style: 'filled')
  else
    as_a = graph.add_nodes(as_a_desc)
  end

  as_b = nil
  if(asns[1] == '64778')
    as_b = graph.add_nodes(as_b_desc, fillcolor: 'lightblue', style: 'filled')
  elsif(asns[1].to_i == vofr_east_paths.local_asn.to_i) then
    as_b = graph.add_nodes(as_b_desc, fillcolor: 'lightyellow', style: 'filled')
  elsif(asns[1].to_i == vofr_west_paths.local_asn.to_i) then
    as_b = graph.add_nodes(as_b_desc, fillcolor: 'lightyellow', style: 'filled')
  else
    as_b = graph.add_nodes(as_b_desc)
  end
  
  if(cgi.params.keys.include? 'directed') then
    graph.add_edges(as_a, as_b, dir: 'forward')
  else
    graph.add_edges(as_a, as_b, dir: 'none')
  end
end

#print cgi.http_header('image/png')
#print graph.output(png: nil)

ENV['PATH'] = '/usr/bin:/bin'
if(__dir__.include? 'gopher') then
  # gophernicus doesn't want headers, just the data
  print(graph.output(png: String))
else
  cgi.out('image/png') { graph.output(png: String) }
end

