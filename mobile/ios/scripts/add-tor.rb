# Links the Tor built into the app (KaspaChatTor.xcframework, made by tools/build-apple.sh) into the App target (run once;
# idempotent). The xcframework is built on a Mac and not committed; this only records where it goes.
#   GEM_HOME=… ruby mobile/ios/scripts/add-tor.rb   (xcodeproj gem 1.28.1)
require 'xcodeproj'

# What the Rust static library needs from the system beyond what an app links anyway (iconv for the libc crate; sysinfo,
# used by Arti's memory quota). tools/build-apple.sh checks this against rustc's own list and stops if it grows.
TOR_LDFLAGS = ['-framework', 'CoreFoundation', '-framework', 'IOKit', '-liconv'].freeze

root = File.expand_path('..', __dir__)
project = Xcodeproj::Project.open(File.join(root, 'App/App.xcodeproj'))
app = project.targets.find { |t| t.name == 'App' }

ref = project.frameworks_group.files.find { |f| f.path == 'KaspaChatTor.xcframework' } ||
      project.frameworks_group.new_reference('KaspaChatTor.xcframework', :project)
ref.last_known_file_type = 'wrapper.xcframework'
app.frameworks_build_phase.add_file_reference(ref, true)

app.build_configurations.each do |c|
  flags = Array(c.build_settings['OTHER_LDFLAGS'] || ['$(inherited)'])
  flags = ['$(inherited)'] + flags.reject { |f| f == '$(inherited)' }
  TOR_LDFLAGS.slice_before { |f| f.start_with?('-') }.each { |g| flags += g unless flags.each_cons(g.size).include?(g) }
  c.build_settings['OTHER_LDFLAGS'] = flags
end
project.save
puts 'ok'
