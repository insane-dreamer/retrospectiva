# Be sure to restart your server when you modify this file

RETROSPECTIVA_VERSION = '1.9.910'

# Specifies gem version of Rails to use when vendor/rails is not present
RAILS_GEM_VERSION = '2.3.4' unless defined? RAILS_GEM_VERSION

# Bootstrap the Rails environment, frameworks, and default configuration
require File.join(File.dirname(__FILE__), 'boot')

Rails::Initializer.run do |config|
  # Settings in config/environments/* take precedence over those specified here.
  # Application configuration should go into files in config/initializers
  # -- all .rb files in that directory are automatically loaded.
  # See Rails::Configuration for more options.

  # Skip frameworks you're not going to use. To use Rails without a database
  # you must remove the Active Record framework.
  config.frameworks -= [ :active_resource ]

  # Specify gems that this application depends on. 
  # They can then be installed with "rake gems:install" on new installations.
  config.gem 'rack', :lib => 'rack', :source => 'http://gems.rubyforge.org', :version => '1.0.0'
  config.gem 'mislav-will_paginate', :lib => 'will_paginate', :source => 'http://gems.github.com', :version => '>= 2.3.8'
  config.gem 'mbleigh-acts-as-taggable-on', :lib => 'acts-as-taggable-on', :source => 'http://gems.github.com', :version => '>= 1.0.3' 
  
  # Skip if installed via Single-Step-Installer
  if !File.exist?(File.join(RAILS_ROOT, 'vendor', 'gems')) || $gems_rake_task 
    config.gem 'RedCloth', :lib => 'redcloth', :version => '>= 4.1.9'
  end
  
  # Only load the plugins named here, in the order given. By default, all plugins 
  # in vendor/plugins are loaded in alphabetical order.
  # :all can be used as a placeholder for all plugins not explicitly named
  # config.plugins = [ :enkoder, :retro_i18n, :retro_search, :validates_as_email, :wiki_engine ]

  # Add additional load paths for your own custom dirs
  config.load_paths += [
#    "#{RAILS_ROOT}/vendor/coderay-0.7.4/lib"
  ].flatten

  config.controller_paths += [
    "#{RAILS_ROOT}/lib/retrospectiva/extension_manager/controllers"
  ].flatten

  # Force all environments to use the same logger level
  # (by default production uses :info, the others :debug)
  # config.log_level = :debug

  # Make Time.zone default to the specified zone, and make Active Record store time values
  # in the database in UTC, and return them converted to the specified local zone.
  # Run "rake -D time" for a list of tasks for finding time zone names. Uncomment to use default local time.
  config.time_zone = 'UTC'

  # Use the database for sessions instead of the cookie-based default,
  # which shouldn't be used to store highly confidential information
  # (create the session table with "rake db:sessions:create")
  # config.action_controller.session_store = :active_record_store

  # Use SQL instead of Active Record's schema dumper when creating the test database.
  # This is necessary if your schema can't be completely dumped by the schema dumper,
  # like if you have constraints or database-specific column types
  # config.active_record.schema_format = :sql

  # Activate observers that should always be running
  unless $gems_rake_task
    config.active_record.observers = 
      'user_observer', 'project_observer', 'group_observer', 
      'changeset_observer', 'ticket_observer', 'ticket_change_observer'
  end
  
  config.after_initialize do
    RetroEM.load!(config)
    RetroCM.reload!
    Retrospectiva::Previewable.load!
    
    session_key = RetroCM[:general][:basic].setting(:session_key)
    if session_key.default?
      RetroCM[:general][:basic][:session_key] = "#{session_key.value}_#{ActiveSupport::SecureRandom.hex(3)}"
      RetroCM.save!
    end

    ActionController::UrlWriter.reload!
    ActionController::Base.session_options.merge!(
      :key    => RetroCM[:general][:basic][:session_key],
      :secret => Retrospectiva::Session.read_or_generate_secret
    )

    ActionView::Base.sanitized_bad_tags.merge %w(meta iframe frame layer ilayer link object embed bgsound from input select textarea style)
    ActionView::Base.sanitized_allowed_tags.merge %w(table tr td th)
    ActionView::Base.sanitized_allowed_attributes.merge %w(colspan rowspan style)

    ActionController::Base.cache_store = :file_store, RAILS_ROOT + '/tmp/cache'
  end unless $gems_rake_task
end

# Once everything is loaded
unless $gems_rake_task || $rails_rake_task
  RetroAM.load!
end

