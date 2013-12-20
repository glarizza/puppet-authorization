require 'puppet/provider/authorization'

Puppet::Type.type(:authorization_right).provide(:sqlite, :parent => Puppet::Provider::Authorization) do
  commands :security => "/usr/bin/security"
  commands :sw_vers  => "/usr/bin/sw_vers"

  confine    :operatingsystem => :darwin
  confine    :feature         => :sqlite
  defaultfor :feature         => :sqlite
end
