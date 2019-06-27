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
require 'ui/dialog'
require 'authserver/dir/ds389'
require 'authserver/dir/client'
require 'socket'
Yast.import 'UI'
Yast.import 'Icon'
Yast.import 'Label'
Yast.import 'Popup'

# NewDirInst dialog collects setup details as input and eventually creates a new directory server instance.
class NewDirInst < UI::Dialog
  include Yast
  include UIShortcuts
  include I18n
  include Logger

  def initialize
    super
    textdomain 'authserver'
  end

  def dialog_options
    Opt(:decorated)
  end

  def finish_handler
    finish_dialog(:next)
  end

  def dialog_content
    VBox(
        Left(Heading(_('Create New Directory Instance'))),
        HBox(
            Frame(_('General options (mandatory)'),
                  VBox(
                      InputField(Id(:fqdn), Opt(:hstretch), _('Fully qualified host name (e.g. dir.example.net)'), Socket.gethostbyname(Socket.gethostname).first),
                      InputField(Id(:instance_name), Opt(:hstretch), _('Directory server instance name (e.g. MyOrgDirectory)'), ''),
		      InputField(Id(:suffix), Opt(:hstretch), _('Directory suffix (e.g. dc=example,dc=net)'), 'dc='+Socket.gethostbyname(Socket.gethostname).first.split('.',2).last.gsub('.',',dc=')),
                      InputField(Id(:dm_dn), Opt(:hstretch), _('Directory manager DN (e.g. cn=root -> no suffix will be appended)'), 'cn=root'),
                      VStretch(),

                  ),
            ),
            Frame(_('Security options (mandatory)'),
                  VBox(
                      Password(Id(:dm_pass), Opt(:hstretch), _('Directory manager password'), ''),
                      Password(Id(:dm_pass_repeat), Opt(:hstretch), _('Repeat directory manager password'), ''),
		      HBox(
                        InputField(Id(:tls_ca), Opt(:hstretch), _('Server TLS certificate authority in PEM format'), ''),
                        VBox(
                          Label(""),
                          PushButton(Id(:browse_ca), Label.BrowseButton)
                        )
                      ),
		      HBox(
                        InputField(Id(:tls_cert), Opt(:hstretch), _('Server TLS certificate in PEM format'), ''),
                        VBox(
                          Label(""),
                          PushButton(Id(:browse_cert), Label.BrowseButton)
                        )
                      ),
                      HBox(
                        InputField(Id(:tls_key), Opt(:hstretch), _('Server TLS certificate key in PEM format'), ''),
                        VBox(
                          Label(""),
                          PushButton(Id(:browse_key), Label.BrowseButton)
                        )
                      ),
                      Password(Id(:key_pass), Opt(:hstretch), _('Certificate key password, if key is encrypted'), ''),
                  ),
            ),
        ),
        HBox(
            PushButton(Id(:ok), Label.OKButton),
            PushButton(Id(:finish), Label.CancelButton),
        ),
        ReplacePoint(Id(:busy), Empty()),
    )
  end

  def browse_ca_handler
    tmpname = UI.QueryWidget(Id(:tls_ca), :Value)	  
    dir = UI.AskForExistingFile(tmpname, '*.pem', _("Choose CA Certificate"))
    if dir
      UI.ChangeWidget(Id(:tls_ca), :Value, dir)
    end
  end

  def browse_cert_handler
    tmpname = UI.QueryWidget(Id(:tls_cert), :Value)
    dir = UI.AskForExistingFile(tmpname, '*.pem', _("Choose Server Certificate"))
    if dir
      UI.ChangeWidget(Id(:tls_cert), :Value, dir)
    end
  end

  def browse_key_handler
    tmpname = UI.QueryWidget(Id(:tls_key), :Value)
    dir = UI.AskForExistingFile(tmpname, '*.pem', _("Choose Server Certificate Key"))
    if dir
      UI.ChangeWidget(Id(:tls_key), :Value, dir)
    end
  end


  def ok_handler
    fqdn = UI.QueryWidget(Id(:fqdn), :Value)
    instance_name = UI.QueryWidget(Id(:instance_name), :Value)
    suffix = UI.QueryWidget(Id(:suffix), :Value)
    dm_dn = UI.QueryWidget(Id(:dm_dn), :Value)
    dm_pass = UI.QueryWidget(Id(:dm_pass), :Value)
    dm_pass_repeat = UI.QueryWidget(Id(:dm_pass_repeat), :Value)
    tls_ca = UI.QueryWidget(Id(:tls_ca), :Value)
    tls_cert = UI.QueryWidget(Id(:tls_cert), :Value)
    tls_key = UI.QueryWidget(Id(:tls_key), :Value)
    key_pass = UI.QueryWidget(Id(:key_pass), :Value)

    # Validate input
    if fqdn == '' || instance_name == ''|| suffix == '' || dm_dn == '' || dm_pass == '' || tls_ca == '' || tls_cert == '' || tls_key == ''
      Popup.Error(_('Please complete setup details. All input fields are mandatory.'))
      return
    end
    if dm_pass_repeat != dm_pass
      Popup.Error(_('The Directory manager password entries do not match.'))
      return
    end
    if !File.exists?(tls_ca) || !File.exists?(tls_cert) || !File.exists?(tls_key)
      Popup.Error(_('TLS certificate authority or certificate/key file does not exist.'))
      return
    end
    if DS389.get_instance_names.include?(instance_name)
      Popup.Error(_('The instance name is already used.'))
      return
    end

    UI.ReplaceWidget(Id(:busy), Label(_('Installing new instance, this may take a minute or two.')))
    begin
      DS389.install_pkgs
      # Collect setup parameters into an INI file and feed it into 389 setup script
      ok = DS389.exec_setup(DS389.gen_setup_ini(fqdn, instance_name, suffix, dm_dn, dm_pass))
      DS389.remove_setup_ini
      if !ok
        Popup.Error(_('Failed to set up new instance! Log output may be found in %s') % [DS_SETUP_LOG_PATH])
        raise
      end
      # Turn on TLS
      if !DS389.install_tls_in_nss(instance_name, tls_ca, tls_cert, tls_key, key_pass)
        Popup.Error(_('Failed to set up new instance! Log output may be found in %s') % [DS_SETUP_LOG_PATH])
        raise
      end
      ldap = LDAPClient.new('ldap://'+fqdn, dm_dn, dm_pass)
      out, ok = ldap.modify(DS389.get_enable_tls_ldif, true)
      DS389.append_to_log(out)
      if !ok
        Popup.Error(_('Failed to enable TLS! Log output may be found in %s') % [DS_SETUP_LOG_PATH])
        raise
      end
      if !DS389.restart(instance_name)
        Popup.Error(_('Failed to restart directory instance, please inspect the journal of dirsrv@%s.service') % [instance_name])
        raise
      end
      if !DS389.add_ca_cert_to_system(tls_ca)
        Popup.Error(_('Failed to install CA certificate to system database! Log output may be found in %s') % [DS_SETUP_LOG_PATH])
	raise
      end
      open('/etc/openldap/ldap.conf', 'w') {|fh|
        fh.puts(DS389.gen_ldap_conf(fqdn, suffix))
      }
      if !DS389.enable(instance_name)
        Popup.Error(_('Failed to enable directory instance, please inspect the journal of dirsrv@%s.service and dirsrv.target. Log output may be found in %s') % [instance_name, DS_SETUP_LOG_PATH])
        raise
      end
      UI.ReplaceWidget(Id(:busy), Empty())
      Popup.Message(_('New instance has been set up! Log output may be found in %s') % [DS_SETUP_LOG_PATH])
      finish_dialog(:next)
    rescue
      # Give user an opportunity to correct mistake
      UI.ReplaceWidget(Id(:busy), Empty())
    end

  end
end
