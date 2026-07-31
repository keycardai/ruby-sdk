# frozen_string_literal: true

require "rspec/core/rake_task"
require "rubocop/rake_task"

GEM_DIRS = %w[oauth mcp a2a].freeze

GEM_DIRS.each do |dir|
  RSpec::Core::RakeTask.new("spec:#{dir}") do |t|
    t.pattern = "#{dir}/spec/**/*_spec.rb"
    t.rspec_opts = "-I#{dir}/spec --require spec_helper"
  end
end

desc "Run specs for every gem"
task spec: GEM_DIRS.map { |dir| "spec:#{dir}" }

RuboCop::RakeTask.new

task default: %i[spec rubocop]
