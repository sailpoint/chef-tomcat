#
# Cookbook Name:: tomcat
# Recipe:: default
#
# Copyright 2010, Opscode, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# required for the secure_password method from the openssl cookbook
::Chef::Recipe.send(:include, Opscode::OpenSSL::Password)

include_recipe "java"

Chef::Log.debug "Tomcat base version: #{node['tomcat']['base_version']}" 

node['tomcat'].each{|k,v| node['tomcat'][k] = v.gsub("tomcat6", "tomcat#{node['tomcat']['base_version']}") if v.kind_of?(String) }

tomcat_pkgs = value_for_platform(
  ["debian","ubuntu"] => {
    "default" => ["tomcat#{node["tomcat"]["base_version"]}","tomcat#{node["tomcat"]["base_version"]}-admin"]
  },
  ["centos","redhat","fedora"] => {
    "default" => ["tomcat#{node["tomcat"]["base_version"]}","tomcat#{node["tomcat"]["base_version"]}-admin-webapps"]
  },
  "default" => ["tomcat#{node["tomcat"]["base_version"]}"]
)

tomcat_pkgs.each do |pkg|
  package pkg do
    action :install
  end
end

directory node['tomcat']['endorsed_dir'] do
  mode "0755"
  recursive true
end

unless node['tomcat']['deploy_manager_apps']
  directory "#{node['tomcat']['webapp_dir']}/manager" do
    action :delete
    recursive true
  end
  file "#{node['tomcat']['config_dir']}/Catalina/localhost/manager.xml" do
    action :delete
  end
  directory "#{node['tomcat']['webapp_dir']}/host-manager" do
    action :delete
    recursive true
  end
  file "#{node['tomcat']['config_dir']}/Catalina/localhost/host-manager.xml" do
    action :delete
  end
end

if node["tomcat"]["redis"]
  remote_file "/usr/share/tomcat#{node["tomcat"]["base_version"]}/lib/jedis-2.1.0.jar" do
    source "https://github.com/downloads/xetorthio/jedis/jedis-2.1.0.jar"
    mode "0644"
    checksum "9f26d25f65d71b89756969a0868df17d5beab8a4631f8076441edf890a17b983"
    owner "tomcat#{node["tomcat"]["base_version"]}"
    group "tomcat#{node["tomcat"]["base_version"]}"
    notifies :restart, "service[tomcat]"
  end
  
  if node["tomcat"]["base_version"] == "6"
    redis_manager_filename = "tomcat-redis-session-manager-1.0.jar"
    redis_manager_checksum = "2d1eba99f18a9e5c930837fe4826ef8ea29237601ef54a0494c74989f507398b"
  else
    redis_manager_filename = "tomcat-redis-session-manager-1.1.jar"
    redis_manager_checksum = "da9f8d44f0bf40327d47ca54596008bd14c0893503e3eadcea97fdc72da8a0e0"
  end
  remote_file "/usr/share/tomcat#{node["tomcat"]["base_version"]}/lib/#{redis_manager_filename}" do
    source "https://github.com/downloads/jcoleman/tomcat-redis-session-manager/#{redis_manager_filename}"
    mode "0644"
    checksum redis_manager_checksum
    owner "tomcat#{node["tomcat"]["base_version"]}"
    group "tomcat#{node["tomcat"]["base_version"]}"
    notifies :restart, "service[tomcat]"
  end
end

service "tomcat" do
  service_name "tomcat#{node["tomcat"]["base_version"]}"
  case node["platform"]
  when "centos","redhat","fedora"
    supports :restart => true, :status => true
  when "debian","ubuntu"
    supports :restart => true, :reload => false, :status => true
  end
  action [:enable, :start]
end

node.set_unless['tomcat']['keystore_password'] = secure_password
node.set_unless['tomcat']['truststore_password'] = secure_password

unless node['tomcat']["truststore_file"].nil?
  java_options = node['tomcat']['java_options'].to_s
  java_options << " -Djavax.net.ssl.trustStore=#{node["tomcat"]["config_dir"]}/#{node["tomcat"]["truststore_file"]}"
  java_options << " -Djavax.net.ssl.trustStorePassword=#{node["tomcat"]["truststore_password"]}"

  node.set['tomcat']['java_options'] = java_options
end

case node["platform"]
when "centos","redhat","fedora"
  template "/etc/sysconfig/tomcat#{node["tomcat"]["base_version"]}" do
    source "sysconfig_tomcat6.erb"
    owner "root"
    group "root"
    mode "0644"
    notifies :restart, "service[tomcat]"
  end
else
  template "/etc/default/tomcat#{node["tomcat"]["base_version"]}" do
    source "default_tomcat6.erb"
    owner "root"
    group "root"
    mode "0644"
    notifies :restart, "service[tomcat]"
  end
end

template "#{node["tomcat"]["config_dir"]}/server.xml" do
  source "server.xml.erb"
  owner "root"
  group "root"
  mode "0644"
  notifies :restart, "service[tomcat]"
end

template "/etc/tomcat#{node['tomcat']['base_version']}/logging.properties" do
  source "logging.properties.erb"
  owner "root"
  group "root"
  mode "0644"
  notifies :restart, "service[tomcat]"
end

unless node['tomcat']["ssl_cert_file"].nil?
  cookbook_file "#{node['tomcat']['config_dir']}/#{node['tomcat']['ssl_cert_file']}" do
    mode "0644"
  end
  cookbook_file "#{node['tomcat']['config_dir']}/#{node['tomcat']['ssl_key_file']}" do
    mode "0644"
  end
  cacerts = ""
  node['tomcat']['ssl_chain_files'].each do |cert|
    cookbook_file "#{node['tomcat']['config_dir']}/#{cert}" do
      mode "0644"
    end
    cacerts = cacerts + "#{cert} "
  end
  script "create_tomcat_keystore" do
    interpreter "bash"
    cwd node['tomcat']['config_dir']
    code <<-EOH
      cat #{cacerts} > cacerts.pem
      openssl pkcs12 -export \
       -inkey #{node['tomcat']['ssl_key_file']} \
       -in #{node['tomcat']['ssl_cert_file']} \
       -chain \
       -CAfile cacerts.pem \
       -password pass:#{node['tomcat']['keystore_password']} \
       -out #{node['tomcat']['keystore_file']}
    EOH
    notifies :restart, "service[tomcat]"
    creates "#{node['tomcat']['config_dir']}/#{node['tomcat']['keystore_file']}"
  end
else
  execute "Create Tomcat SSL certificate" do
    group node['tomcat']['group']
    command "#{node['tomcat']['keytool']} -genkeypair -keystore \"#{node['tomcat']['config_dir']}/#{node['tomcat']['keystore_file']}\" -storepass \"#{node['tomcat']['keystore_password']}\" -keypass \"#{node['tomcat']['keystore_password']}\" -dname \"#{node['tomcat']['certificate_dn']}\""
    umask 0007
    creates "#{node['tomcat']['config_dir']}/#{node['tomcat']['keystore_file']}"
    action :run
    notifies :restart, "service[tomcat]"
  end
end

unless node['tomcat']["truststore_file"].nil?
  cookbook_file "#{node['tomcat']['config_dir']}/#{node['tomcat']['truststore_file']}" do
    mode "0644"
  end
end
