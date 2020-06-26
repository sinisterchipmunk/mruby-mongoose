mruby-mongoose
==============

## Description

Provides the capability to use [Mongoose](https://github.com/cesanta/mongoose)
via mruby.

## Features

At this time, only HTTP and HTTPS webservers are provided. Pull requests
implementing other features of Mongoose will be accepted as long as adequate
test coverage is supplied.

## Install
 - add conf.gem line to `build_config.rb`

```ruby
MRuby::Build.new do |conf|

    # ... (snip) ...

    conf.gem :git => 'https://github.com/sinisterchipmunk/mruby-mongoose.git'
end
```

## Test

```ruby
ruby run_test.rb test
```

## Usage
```ruby
# Create and start the mongoose server
mongoose = Mongoose.new

# Serve HTTP on port 8080
mongoose.start_http 8080

# Serve HTTPS on port 443
mongoose.start_https "server.key", "server.crt", 443

# Process a request. The block should return the response, which should be an
# enumerable responding to #each. Each element of the enumerable may be a
# String or an IO-like. `mruby-mongoose` will call #close on the IO-like after
# reading it.
mongoose.on_http_request do |req|
  # dump request info
  puts [req.connection.id, req.verb, req.path, req.query_string,
        req.headers.inspect, req.body.read]
  # then return a response
  [
    "HTTP/1.1 200 OK\r\n",
    "Content-type: text/plain\r\n\r\n",
    File.open("path/to/file", "r") # will be closed automatically
  ]
end
```

## License

Under MIT license

```
mruby-mongoose - An mruby extension for Mongoose.
Copyright (C) 2020 Colin MacKenzie IV
```
