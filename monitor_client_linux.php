#!/usr/bin/php8.3
<?php

/**
 * Monitor Client Linux
 *
 * 시스템 모니터 클라이언트 스크립트입니다.
 * CLI 환경에서 실행할 수 있습니다.
 *
 * 시스템 상태 정보를 수집하여 MONITOR_SERVER_QUERY_INTERVAL 간격으로
 * MONITOR_SERVER_ADDRESS 서버에 UDP 전송합니다.
 *
 * Version:     0.9
 * PHP Version: 8.0+
 * Dependencies:
 *  - ReactPHP Datagram:  https://github.com/reactphp/datagram
 *  - ReactPHP Stream:    https://github.com/reactphp/stream
 *  - PosixSignalHandler: https://github.com/antibiotics11/posix-signal-handler
 *  - php-shellcommand:   https://github.com/mikehaertl/php-shellcommand
 */

declare(ticks = 1, strict_types = 1);
cli_set_process_title("monitor-client-linux");

require_once(__DIR__ . "/vendor/autoload.php");
use React\Datagram\Factory;
use React\Datagram\Socket;
use React\EventLoop\Loop;
use React\Stream\WritableResourceStream;
use antibiotics11\PosixSignalHandler\PosixSignal;
use antibiotics11\PosixSignalHandler\PosixSignalHandler;
use mikehaertl\shellcommand\Command;

const MONITOR_SERVER_ADDRESS        = "127.0.0.1:12345";   // 서버 주소
const MONITOR_SERVER_QUERY_INTERVAL = 30 * 10;             // 서버에 쿼리할 간격 (초)
const MONITOR_CLIENT_LOG_OUTPUTS    = [                    // 클라이언트 로그를 내보낼 경로
  "/dev/tty",
  "/var/log/monitor_client.log"
];
const NETWORK_STATUS_API_ADDRESS    = "http://localhost/"; // 네트워크 상태 정보를 받아올 API 주소

/**
 * System Status 구조체.
 */
class system_status extends stdClass {
  public function __construct(

    /**
     * @var system_cpu_status|null CPU 상태
     */
    public ?system_cpu_status $cpu_status = null,

    /**
     * @var system_memory_status|null 메모리 상태
     */
    public ?system_memory_status $memory_status = null,

    /**
     * @var system_filesystem_status[] 로컬 파일시스템 상태
     */
    public array $filesystem_statuses = [],

    /**
     * @var system_net_status|null 네트워크 상태
     */
    public ?system_net_status $net_status = null,

    /**
     * @var system_time_info|null 시간
     */
    public ?system_time_info $time_info = null,

    /**
     * @var string[] 로그인한 사용자 목록
     */
    public array $users = [],

    /**
     * @var system_service_status[] 서비스 목록
     */
    public array $services = [],

    /**
     * @var system_net_interface[] 인터페이스 목록
     */
    public array $interfaces = []

  ) {}
}

/**
 * CPU Status 구조체.
 */
class system_cpu_status extends stdClass {
  public function __construct(
    public array  $usage,
    //public int    $temperature = -1
  ) {}
}

class system_cpu_usage extends stdClass {
  public function __construct(
    public int $cpu,      // CPU 번호
    public int $user,     // 사용자 영역 타임.
    public int $system,   //
    public int $nice,     // 커널 영역 타임.
    public int $idle,
  ) {}
}

/**
 * Memory Status 구조체.
 */
class system_memory_status extends stdClass {
  public function __construct(
    public int $mem_total,   // 전체 메모리.
    public int $mem_free,    // 사용 가능한 메모리.
    public int $cached,      // 캐시 메모리.
    public int $swap_total,  // 전체 스왑.
    public int $swap_free,   // 사용 가능한 스왑.
    public int $swap_cached  // 캐시로 사용된 스왑.
  ) {}
}

/**
 * Filesystem Status 구조체.
 */
class system_filesystem_status extends stdClass {
  public function __construct(
    public string $filesystem,
    public int    $size,
    public int    $used,
    public int    $available,
    public string $mounted_on
  ) {}
}

/**
 * Time Info 구조체.
 */
class system_time_info extends stdClass {
  public function __construct(
    public int    $time,     // 현재 시간 (unix timestamp)
    public string $timezone, // 타임존
    public int    $uptime    // 업타임 (s)
  ) {}
}

/**
 * Service Status 구조체.
 */
class system_service_status extends stdClass {
  public function __construct(
    public string $name,            // 서비스 이름.
    public bool   $active  = false, // 서비스 활성화 여부.
    public int    $pid     = 0,     // 서비스 Process ID.
    public string $cpu     = "",    // 서비스가 점유한 CPU 타임.
    public string $memory  = ""     // 서비스가 점유한 메모리 용량.
  ) {}
}

/**
 * Network Status 구조체.
 */
class system_net_status extends stdClass {
  public function __construct(
    public bool                 $connected    = false, // 네트워크 연결 여부.
    public stdClass|string|null $api_response = null   // 네트워크 API에서 받은 정보.
  ) {}
}

/**
 * Network Interface 구조체.
 */
class system_net_interface extends stdClass {
  public function __construct(
    public string $name,               // 인터페이스 이름.
    public bool   $up         = false, // 인터페이스 활성화 여부.
    public array  $addresses  = [],    // 인터페이스에 할당된 주소 목록 (inet_address[]).
    public int    $tx_packets = 0,     // 인터페이스에서 전송된 패킷 수.
    public int    $tx_bytes   = 0,     // 인터페이스에서 전송된 바이트 합.
    public int    $rx_packets = 0,     // 인터페이스에 수신된 패킷 수.
    public int    $rx_bytes   = 0      // 인터페이스에 수신된 바이트 합.
  ) {}
}

/**
 * Inet Address 구조체.
 */
class inet_address extends stdClass {
  public function __construct(
    public string $address, // 주소.
    public int    $family,  // 주소 패밀리.
    public string $netmask  // 넷마스크.
  ) {}
}

/**
 * 메인 함수.
 *
 * @param int $argc
 * @param array $argv
 * @return void
 */
function main(int $argc, array $argv): void {

  if (!gc_enabled()) {
    gc_enable();
  }

  PosixSignalHandler::addHandler(PosixSignal::SIGINT,  "shutdown");
  PosixSignalHandler::addHandler(PosixSignal::SIGTERM, "shutdown");

  $promise = (new Factory())->createClient(MONITOR_SERVER_ADDRESS);
  $promise->then(function (Socket $client): void {

    log_get_streams(MONITOR_CLIENT_LOG_OUTPUTS);

    Loop::addPeriodicTimer(MONITOR_SERVER_QUERY_INTERVAL,
      function () use ($client) {
        static $network_connected = true;
        monitor($client, $network_connected);

        gc_collect_cycles();
        gc_mem_caches();
    });

  });

}

function monitor(Socket $client, bool &$network_connected): void {

  $system_status = system_get_status(NETWORK_STATUS_API_ADDRESS);

  if ($system_status->net_status->connected) {
    if (!$network_connected) {
      log_write("Network connected.", "notice");
    }
    $network_connected = true;
  } else {
    if ($network_connected) {
      log_write("Network seems to be disconnected.", "warning");
    }
    $network_connected = false;
  }

  $message = serialize_structure($system_status);
  if ($message === false) {
    log_write("Failed to serialize message.", "error");
    return;
  }

  $client->send($message);
  log_write(
    sprintf("%d bytes sent.", strlen($message)),
    ($network_connected ? "notice" : "warning")
  );

  unset($system_status);

}

function system_get_status(string $api_address): system_status {
  return new system_status(
    system_get_cpu_status(),
    system_get_memory_status(),
    system_get_filesystem_statuses(),
    system_get_net_status($api_address),
    system_get_time_info(),
    system_get_users(),
    system_get_services(),
    system_get_interfaces()
  );
}

function system_get_cpu_status(): system_cpu_status {
  return new system_cpu_status(
    system_get_cpu_usage(),
    //system_get_cpu_temperature()
  );
}

/**
 * @return system_cpu_usage[]
 */
function system_get_cpu_usage(): array {
  static $stat_file = "/proc/stat";

  $stat = @file($stat_file);
  if ($stat === false) {
    return [];
  }

  $cpu_usage = [];
  foreach ($stat as $line) {
    if (preg_match_all(
      '/cpu(\d)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/',
      $line,
      $matches
    )) {
      $cpu_usage[] = new system_cpu_usage(
        (int)trim($matches[1][0]),
        (int)trim($matches[2][0]),
        (int)trim($matches[3][0]),
        (int)trim($matches[4][0]),
        (int)trim($matches[5][0])
      );
    }
  }

  return $cpu_usage;

}

/**
 * 시스템의 메모리 사용량을 Byte 크기로 가져온다.
 *
 * @return system_memory_status
 */
function system_get_memory_status(): system_memory_status {

  static $meminfo_file = "/proc/meminfo";

  $memory_status = new system_memory_status(-1, -1, -1, -1, -1, -1);

  $meminfo = @file($meminfo_file);
  if ($meminfo !== false) {
    foreach ($meminfo as $line) {

      if (preg_match_all(
        '/(?i)(MemTotal|MemFree|Cached|SwapCached|SwapTotal|SwapFree)\s?:\s+?(\d+)/',
        $line,
        $matches
      )) {

        if (!isset($matches[1]) || !isset($matches[2])) {
          continue;
        }

        $meminfo_attribute = preg_replace('/(?<!^)[A-Z]/', '_$0', $matches[1][0]);
        $meminfo_attribute = strtolower($meminfo_attribute);
        $meminfo_value     = (int)trim($matches[2][0]);

        $memory_status->{$meminfo_attribute} = $meminfo_value;

      }

    }
  }

  return $memory_status;

}

/**
 * 로컬 파일시스템 목록을 가져온다.
 *
 * @return system_filesystem_status[]
 */
function system_get_filesystem_statuses(): array {

  static $filesystem_command = "/bin/df";

  $filesystem_command_output = execute($filesystem_command);
  $filesystem_lines = preg_split('/\r\n|\r|\n/', $filesystem_command_output);

  $filesystem_statuses = [];
  for ($l = 0; $l < count($filesystem_lines); $l++) {
    if (preg_match_all(
      '/([\w\/\-]+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)%\s+([\w\/]+)/',
      $filesystem_lines[$l],
      $matches
    )) {
      $filesystem_statuses[] = new system_filesystem_status(
        trim($matches[1][0]),
        (int)trim($matches[2][0]),
        (int)trim($matches[3][0]),
        (int)trim($matches[4][0]),
        trim($matches[6][0])
      );
    }
  }

  return $filesystem_statuses;

}

function system_get_time_info(): system_time_info {
  return new system_time_info(
    system_get_time(),
    system_get_timezone(),
    system_get_uptime()["uptime"]
  );
}

/**
 * 시스템의 업타임과 아이들타임을 초 단위로 가져온다.
 *
 * @return int[]
 */
function system_get_uptime(): array {

  static $uptime_file = "/proc/uptime";

  $uptime_in_seconds = -1;
  $idle_in_seconds   = -1;

  $uptime = @file_get_contents($uptime_file);
  if ($uptime !== false) {
    list($uptime_in_seconds, $idle_in_seconds) = explode(" ", $uptime);
  }

  return [
    "uptime" => (int)$uptime_in_seconds,
    "idle"   => (int)$idle_in_seconds
  ];

}

/**
 * 시스템 시간을 Unix Timestamp 형식으로 가져온다.
 *
 * @return int
 */
function system_get_time(): int {

  static $timestamp_command = "/bin/echo \$EPOCHSECONDS";
  static $date_command      = "/bin/date +%s";

  // EPOCHSECONDS 환경 변수를 먼저 확인한다.
  $timestamp_command_output = execute($timestamp_command);
  if (strlen(trim($timestamp_command_output)) != 0) {
    return (int)$timestamp_command_output;
  }

  $date_command_output = execute($date_command);
  if (is_numeric($date_command_output)) {
    return (int)$date_command_output;
  }

  return -1;

}

/**
 * 시스템의 타임존을 문자열로 가져온다.
 *
 * @return string
 */
function system_get_timezone(): string {

  static $timezone_file    = "/etc/timezone";
  static $timezone_command = "/bin/timedatectl | /bin/grep \"Time zone:\"";
  static $timezone_regex   = "/\w+\/\w+/";

  // timezone 파일을 먼저 시도한다.
  $timezone = @file_get_contents($timezone_file);
  if ($timezone !== false && preg_match($timezone_regex, $timezone)) {
    return $timezone;
  }

  $timezone_command_output = execute($timezone_command);
  if (strlen($timezone_command_output) != 0) {
    $timezone = explode(":", $timezone_command_output)[1] ?? "";
    if (preg_match($timezone_regex, $timezone)) {
      return $timezone;
    }
  }

  return "Unknown";

}

/**
 * 현재 로그인한 사용자 목록을 배열로 가져온다.
 *
 * @return string[]
 */
function system_get_users(): array {

  static $users_command = "/bin/users";

  $output = execute($users_command);
  $users = [];

  if (strlen($output) != 0) {
    $users = explode(" ", $output);
  }

  return $users;

}

/**
 * 서비스 목록과 각 서비스의 상태를 배열로 가져온다.
 *
 * @return system_service_status[] Service Status 구조체 배열.
 */
function system_get_services(): array {

  static $service_list_command   = "/usr/sbin/service --status-all";

  $service_list_output = execute($service_list_command, 5);
  $service_list = [];

  if (strlen($service_list_output) == 0) {
    return [];
  }

  $service_list_lines = preg_split('/\r\n|\r|\n/', $service_list_output);
  for ($l = 0; $l < count($service_list_lines); $l++) {

    if (preg_match_all(
      '/\[\s*([+\-])\s*]\s*([\w\-.]*)/',
      $service_list_lines[$l],
      $matches
    )) {

      $service_name = $matches[2][0] ?? "";
      if (strlen($service_name) == 0) {
        continue;
      }

      $service_status = system_get_service_status($service_name);
      $service_list[$service_name] = $service_status;

    }

  }

  return $service_list;

}

/**
 * 서비스 상태 정보를 가져온다.
 *
 * @param string $service_name 서비스 이름.
 * @return system_service_status Service Status 구조체.
 */
function system_get_service_status(string $service_name): system_service_status {

  static $service_status_command = "/usr/sbin/service %s status";

  $service_status_output = execute(
    sprintf($service_status_command, $service_name)
  );
  $service_status = new system_service_status($service_name);

  if (strlen($service_status_output) == 0) {
    return $service_status;
  }

  $service_status_lines = preg_split('/\r\n|\r|\n/', $service_status_output);
  for ($l = 0; $l < count($service_status_lines); $l++) {

    if (preg_match_all(
      '/(?i)(active|pid|memory|cpu)\s?:\s?(\S+)/',
      $service_status_lines[$l],
      $matches
    )) {

      $service_status_key   = $matches[1][0] ?? "";
      $service_status_value = $matches[2][0] ?? "";
      if (strlen($service_status_key) == 0) {
        continue;
      }

      $service_status_key   = strtolower(trim($service_status_key));
      $service_status_value = trim($service_status_value);

      // 속성이 PID인 경우 값을 int형으로 바꾼다.
      if (strcmp($service_status_key, "pid") == 0) {
        $service_status_value = (int)$service_status_value;
      }
      // 속성이 Active인 경우 값을 bool형으로 바꾼다.
      if (strcmp($service_status_key, "active") == 0) {
        $service_status_value = strcasecmp($service_status_value, "active") == 0;
      }

      $service_status->{$service_status_key} = $service_status_value;

    }

  }

  return $service_status;

}

/**
 * API를 사용해 네트워크 상태 정보를 가져온다.
 *
 * @param string $api_address 네트워크 정보를 받아올 API 주소.
 * @return system_net_status Network Status 구조체.
 */
function system_get_net_status(string $api_address): system_net_status {

  $net_status = new system_net_status();

  $api_response = @file_get_contents(
    $api_address,
    false,
    stream_context_create([ "http" => [ "timeout" => 5 ] ])
  );
  if ($api_response !== false) {

    $net_status->connected = true;

    $parsed_api_response = deserialize_structure($api_response);
    if ($parsed_api_response === false) {
      $net_status->api_response = $api_response;
    } else {
      $net_status->api_response = $parsed_api_response;
    }

  }

  return $net_status;

}

/**
 * 네트워크 인터페이스 목록을 가져온다.
 *
 * @return system_net_interface[] Network Interface 구조체 배열.
 */
function system_get_interfaces(): array {

  static $network_devices_file = "/proc/net/dev";

  $network_devices = @file($network_devices_file);
  if ($network_devices === false) {
    return [];
  }

  // 인터페이스별 송수신 정보를 가져온다.
  $configured_devices = [];
  foreach ($network_devices as $line) {

    $tokens = explode(":", $line);
    if (!isset($tokens[1]) || strlen($tokens[1]) == 0) {
      continue;
    }

    list($network_device_name, $network_device_data) = $tokens;
    $network_device_name = trim($network_device_name);
    $network_device_data = trim($network_device_data);

    if (preg_match_all('/\d+/', $network_device_data, $bytes_data)) {
      $configured_devices[$network_device_name] = [
        "rx_bytes"   => (int)$bytes_data[0][0] ?? -1,
        "rx_packets" => (int)$bytes_data[0][1] ?? -1,
        "tx_bytes"   => (int)$bytes_data[0][8] ?? -1,
        "tx_packets" => (int)$bytes_data[0][9] ?? -1
      ];
    }

  }

  // net_get_interface 함수가 없는 경우
  if (!function_exists("net_get_interfaces")) {
    return [];
  }

  // 인터페이스 목록을 가져오지 못한 경우
  $configured_interfaces = net_get_interfaces();
  if ($configured_interfaces === false) {
    return [];
  }

  // 인터페이스별 세부 정보를 가져온다.
  $interfaces = [];
  foreach ($configured_interfaces as $name => $details) {

    $up        = (bool)($details["up"] ?? false);
    $addresses = [];
    $unicast   = $details["unicast"] ?? [];

    foreach ($unicast as $address) {
      if (!isset($address["address"])) {
        continue;
      }
      $addresses[] = new inet_address(
        $address["address"],
        $address["family"],
        $address["netmask"]
      );
    }

    $interfaces[] = new system_net_interface(
      $name, $up, $addresses,
      $configured_devices[$name]["tx_packets"],
      $configured_devices[$name]["tx_bytes"],
      $configured_devices[$name]["rx_packets"],
      $configured_devices[$name]["rx_bytes"]
    );

  }

  return $interfaces;

}

/**
 * 로그 문자열을 정해진 형식으로 포맷팅한다.
 *
 * @param string $log 로그 문자열.
 * @param string $level 로그 레벨 (INFO, NOTICE, WARNING, ERROR).
 * @param int $time 로그 발생 시간 (unix timestamp).
 * @return string 포맷팅된 로그.
 */
function log_get_message(string $log, string $level, int $time = -1): string {

  static $message_format = "[%s]\t\033[%dm[%s]\033[0m\t%s\r\n";

  if ($time == -1) {
    $time = time();
  }

  $time  = date(DATE_RFC7231, $time);
  $level = strtoupper(trim($level));
  $color = match ($level) {
    "INFO"    => 39, // 정보성
    "NOTICE"  => 34, // 알림
    "WARNING" => 33, // 경고
    "ERROR"   => 31  // 심각한 오류
  };

  return sprintf($message_format, $time, $color, $level, $log);

}

/**
 * 로그 스트림을 가져온다.
 *
 * @param string[] $log_outputs
 * @return WritableResourceStream[]
 */
function log_get_streams(array $log_outputs = []): array {

  static $streams = [];

  if (count($log_outputs) > 0) {
    foreach ($log_outputs as $log_output) {
      $resource = fopen($log_output, "a");
      if ($resource === false) {
        $resource = null;
      }
      $streams[$log_output] = new WritableResourceStream($resource);
    }
  }

  return $streams;

}

/**
 * 로그를 작성한다.
 *
 * @param string $log 로그.
 * @param string $level 로그 레벨.
 * @return void
 */
function log_write(string $log, string $level): void {

  $streams = log_get_streams();
  $message = log_get_message($log, $level, time());

  foreach ($streams as $stream) {
    if ($stream->isWritable()) {
      $stream->write($message);
    }
  }

}

/**
 * 구조체를 JSON 직렬화한다.
 *
 * @param stdClass $structure stdClass 구조체.
 * @return string|false JSON 문자열 또는 False.
 */
function serialize_structure(stdClass $structure): string|false {
  return json_encode((array)$structure, JSON_PRETTY_PRINT);
}

/**
 * JSON 문자열을 역직렬화한다.
 *
 * @param string $json JSON 문자열.
 * @return stdClass|false stdClass 구조체 또는 False.
 */
function deserialize_structure(string $json): stdClass|false {

  $decoded = json_decode($json, false);
  if (!($decoded instanceof stdClass)) {
    $decoded = false;
  }

  return $decoded;

}

/**
 * BASH 명령을 실행하여 결과를 문자열로 가져온다.
 *
 * @param string $command 실행할 명령어.
 * @param int $timeout 실행 타임아웃.
 * @return string 실행 결과.
 */
function execute(string $command, int $timeout = 1): string {

  $command = new Command([
    "command" => $command,
    "timeout" => $timeout,
    "locale"  => "en_US.UTF-8"
  ]);
  $execution_result = "";

  if ($command->execute()) {
    $execution_result = $command->getOutput();
  }

  unset($command);
  return $execution_result;

}

/**
 * 스크립트 실행을 종료한다.
 *
 * @param bool $by_error 오류에 의한 종료인지 여부.
 * @return void
 */
function shutdown(bool $by_error = false): void {

  $streams = log_get_streams();
  foreach ($streams as $stream) {
    if (
      $stream instanceof WritableResourceStream &&
      $stream->isWritable()
    ) {
      $stream->close();   // 로그 스트림을 모두 닫는다.
    }
  }

  exit($by_error ? 0 : 1);

}

main($_SERVER["argc"], $_SERVER["argv"]);