# Copyright (c) 2017 SUSE LINUX GmbH, Nuernberg, Germany.
# This program is free software; you can redistribute it and/or modify it under
# the terms of version 2 of the GNU General Public License as published by the
# Free Software Foundation.
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
# You should have received a copy of the GNU General Public License along with
# this program; if not, contact SUSE LINUX GmbH.

# Authors:      Howard Guo <hguo@suse.com>

require 'yast'
require 'open3'
require 'fileutils'

# DS_SETUP_LOG_PATH is the path to progress and debug log file for setting up a new directory instance.
DS_SETUP_LOG_PATH = '/root/yast2-auth-server-dir-setup.log'
# DS_SETUP_INI_PATH is the path to parameter file for setting up new directory instance.
# Place the file under root directory because there are sensitive details in it.
DS_SETUP_INI_PATH = '/root/yast2-auth-server-dir-setup.ini'

# DS389 serves utility functions for setting up a new instance of 389 directory server.
class DS389
  include Yast

  # install_pkgs installs software packages mandatory for setting up 389 directory server.
  def self.install_pkgs
    Yast.import 'Package'
    # DoInstall never fails
    Package.DoInstall(['389-ds', 'openldap2-client'].delete_if {|name| Package.Installed(name)})
  end

  # get_instance_names returns an array of directory instance names already present in the system.
  def self.get_instance_names
    return Dir['/etc/dirsrv/slapd-*'].map {|full_path| File.basename(full_path).sub('slapd-', '')}
  end

  # gen_setup_ini generates INI file content with parameters for setting up directory server.
  def self.gen_setup_ini(fqdn, instance_name, suffix, dm_dn, dm_pass)
    return "[General]
FullMachineName=#{fqdn}
SuiteSpotUserID=dirsrv
SuiteSpotGroup=dirsrv

[slapd]
ServerPort=389
ServerIdentifier=#{instance_name}
Suffix=#{suffix}
RootDN=#{dm_dn}
RootDNPwd=#{dm_pass}
AddSampleEntries=No
"
  end

  # exec_setup runs setup-ds.pl using input parameters file content.
  # The output of setup script is written into file /root/yast2-auth-server-dir-setup.log
  # Returns true only if setup was successful.
  def self.exec_setup(content)
    open(DS_SETUP_INI_PATH, 'w') {|fh| fh.puts(content)}
    stdin, stdouterr, result = Open3.popen2e('/usr/sbin/setup-ds.pl', '--debug', '--silent', '-f', DS_SETUP_INI_PATH)
    append_to_log(stdouterr.readlines.join('\n'))
    stdin.close
    return result.value.exitstatus == 0
  end

  # remove_setup_ini removes the setup INI file.
  def self.remove_setup_ini
    File.delete(DS_SETUP_INI_PATH)
  end

  # append_to_log appends current time and content into log file placed under /root/.
  def self.append_to_log(content)
    open(DS_SETUP_LOG_PATH, 'a') {|fh|
      fh.puts(Time.now)
      fh.puts(content)
    }
  end

  # enable_krb_schema enables kerberos schema in the directory server and then restarts the directory server.
  # Returns true only if server restarted successfully.
  def self.enable_krb_schema(instance_name)
    ::FileUtils.copy('/usr/share/dirsrv/data/60kerberos.ldif', '/etc/dirsrv/slapd-' + instance_name + '/schema/60kerberos.ldif')
    return self.restart(instance_name)
  end

  # make sure the dir389 instance is started prior kdc and kadmin
  def self.set_ds389_dep(instance_name)
    _, _, result = Open3.popen2e('/usr/bin/sed', '-i', 's/^Before=.*/Before=radiusd.service krb5kdc.service kadmind.service/', '/etc/systemd/system/dirsrv@' + instance_name + '.service')
    _, _, result = Open3.popen2e('/usr/bin/systemctl', '--system', 'daemon-reload')
    return result.value.exitstatus == 0
  end

  # restart the directory service specified by the instance name. Returns true only on success.
  def self.restart(instance_name)
    _, _, result = Open3.popen2e('/usr/bin/systemctl', 'restart', 'dirsrv@' + instance_name)
    return result.value.exitstatus == 0
  end

  # enable the directory service specified by the instance name. Returns true only on success.
  def self.enable(instance_name)
    _, _, result = Open3.popen2e('/usr/bin/cp', '/usr/lib/systemd/system/dirsrv@.service', '/etc/systemd/system/dirsrv@' + instance_name + '.service')
    if result.value.exitstatus != 0
        return false
    end
    _, _, result = Open3.popen2e('/usr/bin/sed', '-i', 's/^WantedBy=.*/WantedBy=multi-user.target dirsrv.target/', '/etc/systemd/system/dirsrv@' + instance_name + '.service')
    _, _, result = Open3.popen2e('/usr/bin/systemctl', '--system', 'daemon-reload')
    if result.value.exitstatus != 0
        return false
    end
    _, _, result = Open3.popen2e('/usr/bin/systemctl', 'enable', 'dirsrv@' + instance_name + '.service')
    _, _, result = Open3.popen2e('/usr/bin/systemctl', 'enable', 'dirsrv.target')
    if result.value.exitstatus != 0
        return false
    end
    _, _, result = Open3.popen2e('/usr/bin/systemctl', 'start', 'dirsrv.target')
    return result.value.exitstatus == 0
  end

  # install_tls_in_nss copies the specified CA and pkcs12 certificate+key into NSS database of 389 instance.
  def self.install_tls_in_nss(instance_name, ca_path, cert_path, key_path, key_pass)
    instance_dir = '/etc/dirsrv/slapd-' + instance_name
    # Put CA certificate into NSS database
    _, stdouterr, result = Open3.popen2e('/usr/bin/certutil', '-A', '-d', instance_dir, '-n', 'ca_cert', '-t', 'C,,', '-i', ca_path)
    append_to_log(stdouterr.readlines.join('\n'))
    if result.value.exitstatus != 0
      return false
    end
    #generate a pk12 file
    _, stdouterr, result = Open3.popen2e('/usr/bin/openssl', 'pkcs12', '-export', '-in', cert_path, '-inkey', key_path, '-name', 'Server-Cert', '-out', instance_dir + '/servercert.pk12', '-passin', 'pass:' + key_pass, '-passout', 'pass:' + key_pass)
    append_to_log(stdouterr.readlines.join('\n'))
    if result.value.exitstatus != 0
      return false
    end
    # Put TLS certificate and key into NSS database
    _, stdouterr, result = Open3.popen2e('/usr/bin/pk12util', '-d', instance_dir, '-W', key_pass, '-K', '', '-i', instance_dir + '/servercert.pk12')
    append_to_log(stdouterr.readlines.join('\n'))
    _, stdouterr, result2 = Open3.popen2e('/usr/bin/rm', instance_dir + '/servercert.pk12')
    if result.value.exitstatus != 0
      return false
    end
    return true
  end

  # add the CA certificate into systems ca-certifcates
  def self.add_ca_cert_to_system(ca_path)
    _, stdouterr, result = Open3.popen2e('/usr/bin/cp', ca_path, '/etc/pki/trust/anchors/')
    append_to_log(stdouterr.readlines.join('\n'))
    if result.value.exitstatus != 0
      return false
    end
    _, stdouterr, result = Open3.popen2e('/usr/sbin/update-ca-certificates')
    append_to_log(stdouterr.readlines.join('\n'))
    if result.value.exitstatus != 0
      return false
    end
    return true
  end

  def self.gen_ldap_conf(fqdn, suffix)
    return 'URI ldaps://'+fqdn+'
base '+suffix
  end


  # get_enable_tls_ldif returns LDIF data that can be
  def self.get_enable_tls_ldif
    return 'dn: cn=encryption,cn=config
changetype: modify
replace: nsSSL3
nsSSL3: off
-
replace: nsSSLClientAuth
nsSSLClientAuth: allowed
-
add: nsSSL3Ciphers
nsSSL3Ciphers: +all

dn: cn=config
changetype: modify
add: nsslapd-security
nsslapd-security: on
-
replace: nsslapd-ssl-check-hostname
nsslapd-ssl-check-hostname: off

dn: cn=RSA,cn=encryption,cn=config
changetype: add
objectclass: top
objectclass: nsEncryptionModule
cn: RSA
nsSSLPersonalitySSL: Server-Cert
nsSSLToken: internal (software)
nsSSLActivation: on'
  end
end
