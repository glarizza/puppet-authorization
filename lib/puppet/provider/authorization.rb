require 'facter'
require 'facter/util/plist'
require 'puppet'
require 'tempfile'

class Puppet::Provider::Authorization < Puppet::Provider
  ## This should be confined based on macosx_productversion
  ## but puppet resource doesn't make the facts available and
  ## that interface is heavily used with this provider.
  #if Puppet::FileSystem::File.exist?("/usr/bin/sw_vers")
  #  product_version = sw_vers "-productVersion"

  #  confine :true => unless /^10\.[0-4]/.match(product_version)
  #    true
  #  end
  #end

  AuthDB = "/var/db/auth.db"

  @parsed_auth_db = {}

  # This map exists due to the use of hyphens and reserved words in
  # the authorization schema.
  PuppetToNativeAttributeMap = {  :allow_root => "allow-root",
    :authenticate_user => "authenticate-user",
    :auth_class => "class",
    :k_of_n => "k-of-n",
    :session_owner => "session-owner", }

  class << self
    attr_accessor :parsed_auth_db
    attr_accessor :comments

    def prefetch(resources)
      self.populate_parsed_auth_db
    end

    def instances
      unless self.parsed_auth_db
        self.prefetch(nil)
      end
      self.parsed_auth_db.collect do |k,v|
        new(:name => k)
      end
    end

    def connect_to_auth_db
      @auth_db_connection ||= SQLite3::Database.open AuthDB
    end

    def get_list_of_rules_and_rights
      auth_hash      = {}
      db             = connect_to_auth_db
      array_of_rules = (db.execute 'select * from rules').collect { |f| f[1] }
      array_of_rules.each do |rule|
        begin
          auth_hash[rule] = Plist::parse_xml(security(['authorizationdb', 'read', rule]))
        rescue Puppet::ExecutionFailure => e
          raise Puppet::Error "Could not read value for key #{rule}: Error: #{e.inspect}"
        end
      end
      auth_hash
    end

    def populate_parsed_auth_db
      # Call out to the get_list_of_rules_and_rights method in the provider
      # NOTE: This method is not defined here, and must be defined in the
      #       child provider.
      auth_hash = get_list_of_rules_and_rights
      raise Puppet::Error.new("Cannot parse: #{AuthDB}") if not auth_hash
      self.parsed_auth_db = auth_hash.dup
    end

  end

  # standard required provider instance methods

  def initialize(resource)
    unless self.class.parsed_auth_db
      self.class.prefetch(resource)
    end
    super
  end


  def create
    # we just fill the @property_hash in here and let the flush method
    # deal with it rather than repeating code.
    new_values = {}
    validprops = Puppet::Type.type(resource.class.name).validproperties
    validprops.each do |prop|
      next if prop == :ensure
      if value = resource.should(prop) and value != ""
        new_values[prop] = value
      end
    end
    @property_hash = new_values.dup
  end

  def destroy
    # We explicitly delete here rather than in the flush method.
    destroy_rule
  end

  def exists?
    !!self.class.parsed_auth_db.has_key?(resource[:name])
  end


  def flush
    # deletion happens in the destroy methods
    if resource[:ensure] != :absent
      flush_rule
      @property_hash.clear
    end
  end


  # utility methods below

  def destroy_rule
    security "authorizationdb", :remove, resource[:name]
  end

  def flush_rule
    # first we re-read the right just to make sure we're in sync for
    # values that weren't specified in the manifest. As we're supplying
    # the whole plist when specifying the right it seems safest to be
    # paranoid given the low cost of quering the db once more.
    cmds = []
    cmds << :security << "authorizationdb" << "read" << resource[:name]
    output = execute(cmds, :failonfail => false, :combine => false)
    current_values = Plist::parse_xml(output)
    current_values ||= {}
    specified_values = convert_plist_to_native_attributes(@property_hash)

    # take the current values, merge the specified values to obtain a
    # complete description of the new values.
    new_values = current_values.merge(specified_values)
    set_rule(resource[:name], new_values)
  end

  def set_rule(name, values)
    # Both creates and modifies rights as it simply overwrites them.
    # The security binary only allows for writes using stdin, so we
    # dump the values to a tempfile.
    values = convert_plist_to_native_attributes(values)
    tmp = Tempfile.new('puppet_macauthorization')
    begin
      Plist::Emit.save_plist(values, tmp.path)
      cmds = []
      cmds << :security << "authorizationdb" << "write" << name
      execute(cmds, :failonfail => false, :combine => false, :stdinfile => tmp.path.to_s)
    rescue Errno::EACCES => e
      raise Puppet::Error.new("Cannot save rule to #{tmp.path}: #{e}")
    ensure
      tmp.close
      tmp.unlink
    end
  end

  def convert_plist_to_native_attributes(propertylist)
    # This mainly converts the keys from the puppet attributes to the
    # 'native' ones, but also enforces that the keys are all Strings
    # rather than Symbols so that any merges of the resultant Hash are
    # sane. The exception is booleans, where we coerce to a proper bool
    # if they come in as a symbol.
    newplist = {}
    propertylist.each_pair do |key, value|
      next if key == :ensure     # not part of the auth db schema.
      next if key == :auth_type  # not part of the auth db schema.
      case value
      when true, :true
        value = true
      when false, :false
        value = false
      end
      new_key = key
      if PuppetToNativeAttributeMap.has_key?(key)
        new_key = PuppetToNativeAttributeMap[key].to_s
      elsif not key.is_a?(String)
        new_key = key.to_s
      end
      newplist[new_key] = value
    end
    newplist
  end

  def retrieve_value(resource_name, attribute)
    # We set boolean values to symbols when retrieving values
    raise Puppet::Error.new("Cannot find #{resource_name} in auth db") if not self.class.parsed_auth_db.has_key?(resource_name)

    if PuppetToNativeAttributeMap.has_key?(attribute)
      native_attribute = PuppetToNativeAttributeMap[attribute]
    else
      native_attribute = attribute.to_s
    end

    if self.class.parsed_auth_db[resource_name].has_key?(native_attribute)
      value = self.class.parsed_auth_db[resource_name][native_attribute]
      case value
      when true, :true
        value = :true
      when false, :false
        value = :false
      end

      @property_hash[attribute] = value
      return value
    else
      @property_hash.delete(attribute)
      return ""  # so ralsh doesn't display it.
    end
  end


  # property methods below
  #
  # We define them all dynamically

  properties = [  :allow_root, :authenticate_user, :auth_class, :comment,
    :group, :k_of_n, :mechanisms, :rule, :session_owner,
    :shared, :timeout, :tries ]

  properties.each do |field|
    define_method(field.to_s) do
      retrieve_value(resource[:name], field)
    end

    define_method(field.to_s + "=") do |value|
      @property_hash[field] = value
    end
  end

end

