assert 'Mongoose http connection' do
  mg = Mongoose.new
  assert_equal false, mg.running_http?, 'should indicate http is not running'
  mg.stop_http # should be safe to stop a stopped server

  mg.start_http 8184
  assert_equal true, mg.running_http?, 'should indicate http is running'
  mg.on_http_request do |req|
    request = req
    ["HTTP/1.0 200 OK\r\n\r\n", req.body.read]
  end
  socket = TCPSocket.new('127.0.0.1', 8184)
  resp = begin
           mg.poll(100) # unsure why necessary, must this happen between connect & write?
           socket.write("GET / HTTP/1.1\r\nContent-Length: 5\r\n\r\nHello")
           3.times { mg.poll(100) }
           socket.sysread(1024)
         ensure
           socket.close
         end
  assert_equal "HTTP/1.0 200 OK\r\n\r\nHello", resp

  mg.stop_http
  assert_equal true, !mg.running_http?, 'should indicate http is not running'
end

assert 'Mongoose http with IO in response' do
  mg = Mongoose.new
  mg.start_http 8185
  file = File.open(File.join(File.dirname(__FILE__), "../.gitignore"), 'r')
  mg.on_http_request do |req|
    request = req
    ["HTTP/1.0 200 OK\r\n\r\n", file]
  end

  socket = TCPSocket.new('127.0.0.1', 8185)
  resp = begin
           mg.poll(100) # unsure why necessary, must this happen between connect & write?
           socket.write("GET / HTTP/1.1\r\n\r\n")
           3.times { mg.poll(100) }
           socket.sysread(1024)
         ensure
           socket.close
         end
  assert_equal true, file.closed?,         'file should be closed'
  assert_equal true, !!resp.index("tmp/"), 'response should contain tmp/'
end

assert 'Mongoose http with a longer request body' do
  mg = Mongoose.new
  mg.start_http 8183
  mg.on_http_request do |req|
    request = req
    ["HTTP/1.0 200 OK\r\n\r\n", req.body.read]
  end

  socket = TCPSocket.new('127.0.0.1', 8183)
  message = "this is a test request " * 3
  resp = begin
           mg.poll(100) # unsure why necessary, must this happen between connect & write?
           socket.write("POST / HTTP/1.1\r\nContent-length: #{message.length}\r\n\r\n#{message}")
           3.times { mg.poll(100) }
           socket.sysread(1024)
         ensure
           socket.close
         end
  assert_equal "HTTP/1.0 200 OK\r\n\r\n#{message}", resp
end

assert 'HTTP keep-alive' do
  mg = Mongoose.new
  mg.start_http 8186
  mg.on_http_request do |req|
    request = req
    ["HTTP/1.0 200 OK\r\n\r\n", req.body.read]
  end

  socket = TCPSocket.new('127.0.0.1', 8186)
  begin
    req = "GET / HTTP/1.1\r\nConnection: keep-alive\r\n\r\n"
    mg.poll(100) # unsure why necessary, must this happen between connect & write?
    socket.write(req)
    3.times { mg.poll(100) }
    msg1 = ''
    msg1 << socket.sysread(1024)
    assert_equal "HTTP/1.0 200 OK\r\n\r\n", msg1

    socket.write(req)
    3.times { mg.poll(100) }
    msg2 = ''
    msg2 << socket.sysread(1024)# until socket.eof? || msg2["\r\n\r\n"]
    assert_equal "HTTP/1.0 200 OK\r\n\r\n", msg2
  ensure
    socket.close
  end
end
