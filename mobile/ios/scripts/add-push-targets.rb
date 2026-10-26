# Adds the iPhone push pieces to the Xcode project (run once; idempotent): the app's own plugin and bridge controller,
# the app's entitlements, and the Notification Service Extension target embedded in the app.
#   GEM_HOME=… ruby mobile/ios/scripts/add-push-targets.rb   (xcodeproj gem 1.28.1)
require 'xcodeproj'

root = File.expand_path('..', __dir__)
project = Xcodeproj::Project.open(File.join(root, 'App/App.xcodeproj'))
app = project.targets.find { |t| t.name == 'App' }
app_group = project.main_group.find_subpath('App', false)

%w[MainViewController.swift KaspaChatNativePlugin.swift].each do |f|
  next if app_group.files.any? { |x| x.path == f }
  app.source_build_phase.add_file_reference(app_group.new_reference(f))
end
app_group.new_reference('App.entitlements') unless app_group.files.any? { |x| x.path == 'App.entitlements' }
app.build_configurations.each { |c| c.build_settings['CODE_SIGN_ENTITLEMENTS'] = 'App/App.entitlements' }

unless project.targets.any? { |t| t.name == 'NotificationService' }
  nse = project.new_target(:app_extension, 'NotificationService', :ios, '15.0')
  group = project.main_group.new_group('NotificationService', 'NotificationService')
  nse.source_build_phase.add_file_reference(group.new_reference('NotificationService.swift'))
  group.new_reference('Info.plist')
  group.new_reference('NotificationService.entitlements')
  nse.build_configurations.each do |c|
    s = c.build_settings
    s['PRODUCT_BUNDLE_IDENTIFIER'] = 'com.kaspaguy.kaspachat.NotificationService'
    s['INFOPLIST_FILE'] = 'NotificationService/Info.plist'
    s['CODE_SIGN_ENTITLEMENTS'] = 'NotificationService/NotificationService.entitlements'
    s['SWIFT_VERSION'] = '5.0'
    s['TARGETED_DEVICE_FAMILY'] = '1,2'
    s['MARKETING_VERSION'] = '$(inherited)'
    s['SKIP_INSTALL'] = 'YES'
    s['GENERATE_INFOPLIST_FILE'] = 'NO'
    s['LD_RUNPATH_SEARCH_PATHS'] = ['$(inherited)', '@executable_path/Frameworks', '@executable_path/../../Frameworks']
  end
  nse.frameworks_build_phase.add_file_reference(project.frameworks_group.new_file('System/Library/Frameworks/UserNotifications.framework', :sdk_root))
  app.add_dependency(nse)
  embed = app.new_copy_files_build_phase('Embed Foundation Extensions')
  embed.symbol_dst_subfolder_spec = :plug_ins
  embed.add_file_reference(nse.product_reference).settings = { 'ATTRIBUTES' => ['RemoveHeadersOnCopy'] }
end
project.save
puts 'ok'
