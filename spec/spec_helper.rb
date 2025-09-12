# frozen_string_literal: true

require "wots"
require "json"

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = ".rspec_status"

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end

def load_fixture(relative_path)
  path = File.join(File.dirname(__FILE__), 'fixtures', relative_path)
  JSON.parse(File.read(path))
end