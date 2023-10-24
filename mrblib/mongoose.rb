class Mongoose
  VERSION = '0.0.1'

  class Error < RuntimeError; end
  class BindError < Error; end

  class Connection
    @@next_id = 1

    attr_reader :id

    def initialize
      @id = @@next_id
      @@next_id += 1
    end
  end

  class Request
    attr_reader :connection, :headers, :verb, :path, :query_string, :body

    def initialize(conn, headers, verb, path, query_string, body)
      @connection = conn
      @headers = headers
      @verb = verb.downcase
      @path = path
      @query_string = query_string.size == 0 ? nil : query_string
      @body = body
    end
  end

  def running_http?
    !!@http
  end

  def running_https?
    !!@https
  end

  def on_http_request(&block)
    @callback = block
  end

  private def process_http_request(conn, *args)
    result = if @callback
               @callback.call Request.new(conn, *args)
             else
               [
                 "HTTP/1.0 503 Gateway Unavailable",
                 "Content-type: text/plain",
                 "",
                 "503 Gateway Unavailable"
               ]
             end
    result.each do |part|
      if part.respond_to?(:read)
        conn.write part.read
        part.close if part.respond_to?(:close)
      else
        conn.write part
      end
    end
  end
end
