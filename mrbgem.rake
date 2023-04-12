MRuby::Gem::Specification.new('mruby-mongoose') do |spec|
  spec.license = 'MIT'
  spec.authors = 'sinisterchipmunk@gmail.com'
  spec.version = "0.0.1"

  spec.cc.include_paths << "#{spec.dir}/mongoose"
  spec.cc.include_paths << "#{File.dirname spec.dir}/mruby-polarssl/polarssl/include"
  spec.cc.include_paths << "#{spec.dir}/tmp/mruby/build/mrbgems/mruby-polarssl/polarssl/include"
  spec.cc.include_paths << "#{spec.build_dir}/../../../repos/host/mruby-polarssl/polarssl/include"

  # HACK deal with not having fseeko64 on android-23
  # spec.cc.flags << '-Dfseeko=fseeko -Dfseeko64=fseeko -D_FILE_OFFSET_BITS=32'
  spec.cc.flags << '-Wall -W -Wdeclaration-after-statement -DHAVE_USLEEP'
  spec.cc.flags << '-DMG_ENABLE_CALLBACK_USERDATA=1 -DMG_ENABLE_SSL=1 -DMG_DISABLE_HTTP_DIGEST_AUTH=1 -DCS_DISABLE_MD5=1 -DMG_SSL_IF=MG_SSL_IF_MBEDTLS'

  srcs = ["#{spec.dir}/mongoose/mongoose.c"]
  spec.objs += srcs.map { |f| f.relative_path_from(dir).pathmap("#{build_dir}/%X.o") }

  spec.add_dependency 'mruby-stringio'
  spec.add_dependency 'mruby-io'
  spec.add_dependency 'mruby-polarssl'

  spec.add_test_dependency 'mruby-socket'
end
