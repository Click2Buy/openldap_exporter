# REQUIREMENTS
require 'prometheus_exporter'
require 'prometheus_exporter/server'
# client allows instrumentation to send info to server
require 'prometheus_exporter/client'
require 'prometheus_exporter/instrumentation'
require 'net/http'
require 'openssl'
require 'json'
require 'yaml'
require 'net/ldap'



#METHODS
def underscore name
  name.gsub(/::/, '/').gsub(/([A-Z]+)([A-Z][a-z])/,'\1_\2').gsub(/([a-z\d])([A-Z])/,'\1_\2').tr("-", "_").downcase
end

#VARIABLES
configuration   = YAML.load_file('conf/exporter.yml')
bind            = configuration['exporter']['bind'] || '0.0.0.0'
port            = configuration['exporter']['port'] || 9142
interval        = configuration['exporter']['interval'] || 60
verbose         = configuration['exporter']['verbose'] || false

host            = configuration['ldap']['host'] || 'ldap.exemple.com'
ldap_port       = configuration['ldap']['port'] || '636'
encryption      = configuration['ldap']['encryption'] || 'simple_tls'
base            = configuration['ldap']['base_dn'] || 'dc=exemple, dc=com'
monitor_base_dn = configuration['ldap']['monitor_base_dn'] || 'dc=exemple, dc=com'
credentials     = { username: configuration['ldap']['user_dn'], password: configuration['ldap']['pwd_dn'], method: configuration['ldap']['method'].to_sym }

default_metrics = YAML.load_file('metrics/metrics.yml')
attributes      = default_metrics['metrics'].map{ |metric| metric.last['attribute']}.uniq
values          = {}

# bind is the address, on which the webserver will listen
# port is the port that will provide the /metrics route
server = PrometheusExporter::Server::WebServer.new bind: bind , port: port , verbose: verbose
server.start
#Instance a client and metrics to collect 
client =  PrometheusExporter::LocalClient.new(collector: server.collector)

#Instanciate metrics
group = client.register( :gauge, "ldap_group_entries", "groups in ldap") 
user = client.register( :gauge, "ldap_user_entries", "user in ldap")

#Instanciate monitor metrics
default_metrics['metrics'].each do |metric|
  metric_name     = metric.first
  formatted_key   = underscore(metric_name)
  values["ldap_#{formatted_key}"]  = client.register( metric.last['metricType'].to_sym, "ldap_#{formatted_key}", metric.last['desc']) 
end



#Set metrics
while true

  # entries stats
  ldap = Net::LDAP.new(host: host, port: ldap_port, encryption: encryption, base: base, auth: credentials)  
  group_filter = Net::LDAP::Filter.eq("objectClass", "groupofnames")
  user_filter  = Net::LDAP::Filter.eq("objectClass", "inetorgperson")

  group_entries = ldap.search(filter: group_filter)
  user_entries = ldap.search(filter: user_filter)

  group.observe(group_entries.count)
  user.observe(user_entries.count)

  # monitor stats
  ldap            = Net::LDAP.new(host: host, port: ldap_port, encryption: encryption, base: monitor_base_dn, auth: credentials)  
  monitor_filter  = Net::LDAP::Filter.eq("objectClass", "*")
  result          = ldap.search(filter: monitor_filter, attributes: attributes)

  result.each do |entry|
    metric_match = default_metrics['metrics'].select{|name,metric| metric['dn'] == entry.dn}
    if metric_match.first
      formatted_key   = underscore(metric_match.first.first)
      values["ldap_#{formatted_key}"].observe( "#{entry.send( metric_match.first.last['attribute'] ).first}".to_i )
    end
  end

  sleep interval

end