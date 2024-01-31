<?php

/**
 * NetStat API
 *
 * 네트워크 상태 확인용 HTTP API 스크립트입니다.
 * CGI 또는 FPM 환경에서 실행할 수 있습니다.
 *
 * Version:     1.1
 * PHP Version: 8.0+
 */

declare(ticks = 1, strict_types = 1);

const API_SERVER_NAME     = "NetStat API";
const API_SERVER_HOSTNAME = "localhost";
const API_SERVER_METHODS  = "GET";
const API_SERVER_HTTP_HEADERS = [
  "Server"                       => API_SERVER_NAME,
  "X-Powered-By"                 => API_SERVER_NAME,
  "Cache-Control"                => "no-cache, no-store, must-revalidate, max-age=0",
  "Pragma"                       => "no-cache",
  "Access-Control-Max-Age"       => "0",
  "Access-Control-Allow-Methods" => API_SERVER_METHODS,
  "Access-Control-Allow-Origin"  => "*"
];

/**
 * API Response 구조체.
 */
class api_response extends stdClass {
  public function __construct(
    public string   $status  = "ok",   // HTTP 응답 코드와 동일.
    public ?ip_info $ip_info = null,   // IP Info 구조체.
    public string   $error   = ""      // 오류가 발생한 경우 오류 정보.
  ) {}
}

/**
 * IP Info 구조체.
 */
class ip_info extends stdClass {
  public function __construct(
    public string $ip       = "",      // IP 주소.
    public string $domain   = "",      // 도메인 네임.
    public string $city     = "",      // 도시명.
    public string $country  = "",      // 국가 코드.
    public string $loc      = "",      // 위치 좌표.
    public string $org      = "",      // ISP.
    public string $postal   = "",      // 우편 번호.
    public string $timezone = ""       // 타임존.
  ) {}
}

/**
 * HTTP Response 구조체.
 */
class http_response extends stdClass {
  public function __construct(
    public string $status   = "ok",    // HTTP 응답 코드.
    public array  $headers  = [],      // HTTP 헤더.
    public string $body     = ""       // HTTP 본문.
  ) {}
}

function main(int $argc, array $argv): void {

  if (!http_validate_request($argv["_SERVER"], [
    "hostname" => API_SERVER_HOSTNAME,
    "methods"  => API_SERVER_METHODS
  ])) {                                  // 요청이 보안 검사를 통과하지 못했으면
    api_send_response_error(
      "forbidden",
      "Request Denied."
    );
    return;
  }

  $client_ip         = http_get_client_ip($argv["_SERVER"]);
  $client_url_params = http_get_url_params($argv["_GET"]);

  $ip = network_validate_ip($client_url_params["ip"] ?? $client_ip);
  if ($ip === false) {                   // IP 형식이 올바르지 않으면
    api_send_response_error(
      "bad request",
      "Invalid IP Address."
    );
    return;
  }

  $ip_info = api_get_ip_info($ip);
  if ($ip_info === null) {
    api_send_response_error(             // IP가 없거나 사설 IP인 경우
      "not found",
      "IP Address Not Exist In DB."
    );
    return;
  }

  api_send_response_ip_info($ip_info);

}

/**
 * 외부 API 또는 DB 에서 정보를 가져온다.
 *
 * @param string $ip
 * @return ip_info|null
 */
function api_get_ip_info(string $ip): ?ip_info {

  $ip_info = file_get_contents(
    sprintf("https://ipinfo.io/%s/json", $ip)
  );
  if ($ip_info === false) {
    return null;
  }

  $ip_info = json_decode($ip_info);

  if (isset($ip_info->bogon)) {
    if ($ip_info->bogon) {
      return null;
    }
  }

  return new ip_info(
    $ip_info->ip,
    $ip_info->hostname ?? "",
    $ip_info->city     ?? "",
    $ip_info->region   ?? "",
    $ip_info->loc      ?? "",
    $ip_info->org      ?? "",
    $ip_info->postal   ?? "",
    $ip_info->timezone ?? ""
  );

}

/**
 * API 응답을 전송한다.
 *
 * @param string $status
 * @param ip_info|null $ip_info
 * @param string $error
 * @return void
 */
function api_send_response(string $status, ?ip_info $ip_info, string $error = ""): void {

  $api_response = new api_response($status, $ip_info, $error);
  $http_response = new http_response(
    $api_response->status,
    API_SERVER_HTTP_HEADERS,
    serialize_structure($api_response)
  );

  http_send_response($http_response);

}


/**
 * IP Info API 응답을 전송한다.
 *
 * @param ip_info $ip_info
 * @return void
 */
function api_send_response_ip_info(ip_info $ip_info): void {
  api_send_response("ok", $ip_info);
}

/**
 * 오류가 있는 API 응답을 전송한다.
 *
 * @param string $status
 * @param string $error
 * @return void
 */
function api_send_response_error(string $status, string $error): void {
  api_send_response($status, null, $error);
}


/**
 * HTTP 응답을 전송한다.
 *
 * @param http_response $http_response http_response 객체.
 * @return void
 */
function http_send_response(http_response $http_response): void {

  $http_headers = $http_response->headers;
  $http_body    = sprintf("%s\r\n\r\n", $http_response->body);

  $http_headers["Content-Length"] = strlen($http_body);
  $http_headers["Date"]           = date(DATE_RFC7231, time());
  if (!isset($http_headers["Content-Type"])) {
    $http_headers["Content-Type"] = "application/json;charset=UTF-8";
  }

  http_set_status_code($http_response->status);
  http_set_headers($http_headers);

  printf($http_body);

}

/**
 * HTTP 응답 코드를 설정한다.
 *
 * @param string $status HTTP 상태 구문 (ok, bad request, forbidden, not found).
 * @return void
 */
function http_set_status_code(string $status = "ok"): void {

  $response_code = match (strtolower($status)) {
    "ok"          => 200,
    "bad request" => 400,
    "forbidden"   => 403,
    "not found"   => 404,
    default       => 500
  };

  http_response_code($response_code);

}

/**
 * HTTP 헤더를 설정한다.
 *
 * @param string $header 헤더 속성.
 * @param string $value 헤더 값.
 * @return void
 */
function http_set_header(string $header, string $value): void {
  header(sprintf("%s: %s", $header, $value));
}

/**
 * 여러 개의 HTTP 헤더를 설정한다.
 *
 * @param string[] $headers [속성] => [값] 형식의 배열.
 * @return void
 */
function http_set_headers(array $headers): void {

  foreach ($headers as $header => $value) {
    http_set_header($header, (string)$value);
  }

}

/**
 * HTTP 요청이 유효한지 확인한다.
 *
 * @param array $server _SERVER 전역변수.
 * @param array $server_config 서버 설정.
 * @return bool
 */
function http_validate_request(array $server, array $server_config): bool {

  $server_methods = $server_config["methods"];
  $request_method = $server["REQUEST_METHOD"] ?? "";
  if (!http_validate_methods($server_methods, $request_method)) {
    return false;
  }

  $server_hostname = $server_config["hostname"];
  $request_host    = $server["HTTP_HOST"] ?? "";
  if (!http_validate_host($server_hostname, $request_host)) {
    return false;
  }

  return true;

}

/**
 * HOST 헤더가 유효한지 확인한다.
 *
 * @param string $server_hostname 서버의 도메인 네임.
 * @param string $request_host HOST 헤더 값.
 * @return bool
 */
function http_validate_host(string $server_hostname, string $request_host): bool {
  return strcasecmp(trim($server_hostname), trim($request_host)) == 0;
}

/**
 * 요청 메소드가 유효한지 확인한다.
 *
 * @param string $server_methods 서버에서 처리할 수 있는 메소드 목록.
 * @param string $request_method 요청 메소드.
 * @return bool
 */
function http_validate_methods(string $server_methods, string $request_method): bool {

  $server_allowed_methods = explode(",", $server_methods);
  foreach ($server_allowed_methods as $method) {
    if (strcasecmp(trim($method), trim($request_method)) == 0) {
      return true;
    }
  }

  return false;

}

/**
 * 클라이언트의 IP 주소를 확인한다.
 *
 * @param array $server_params _SERVER 전역변수.
 * @return string 클라이언트의 IP 주소.
 */
function http_get_client_ip(array $server_params): string {

  $client_ip = $server_params["HTTP_X_FORWARDED_FOR"] ?? $server_params["REMOTE_ADDR"];
  return network_validate_ip($client_ip) === false ? "" : $client_ip;

}

/**
 * 클라이언트가 전송한 URL 파라미터를 확인한다.
 *
 * @param array $get_params _GET 전역변수.
 * @return array
 */
function http_get_url_params(array $get_params): array {

  $url_params = [];
  foreach ($get_params as $key => $value) {
    $url_params[strtolower(trim($key))] = trim($value);
  }

  return $url_params;

}

/**
 * 구조체를 JSON 직렬화한다.
 *
 * @param stdClass $structure stdClass 구조체.
 * @return string|false JSON 문자열.
 */
function serialize_structure(stdClass $structure): string|false {
  return json_encode((array)$structure, JSON_PRETTY_PRINT);
}

/**
 * 문자열이 IPv4 또는 IPv6 주소인지 확인한다.
 *
 * @param string $ip 확인할 문자열.
 * @return string|false IP 주소면 그대로 반환하되, 아니면 False.
 */
function network_validate_ip(string $ip): string|false {
  return filter_var($ip, FILTER_VALIDATE_IP) !== false ? $ip : false;
}

main(count($GLOBALS), [ "_SERVER" => $_SERVER, "_GET" => $_GET ]);
