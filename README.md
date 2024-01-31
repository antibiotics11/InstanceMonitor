# InstanceMonitor

네트워크 인스턴스 감시용 시스템 모니터입니다. <br>
PHP 8.0 또는 상위 버전이 필요합니다.

## NetStat API

네트워크 상태 확인용 HTTP API 스크립트입니다. <br>
CGI 또는 FPM 환경에서 실행할 수 있습니다.

### API 요청 예시

```shell
wget http://localhost/net_stat_api.php?ip=8.8.8.8
```

### API 응답 예시

```json
{
  "status": "ok",
  "ip_info": {
    "ip": "8.8.8.8",
    "domain": "dns.google",
    "city": "Mountain View",
    "country": "California",
    "loc": "37.4056,-122.0775",
    "org": "AS15169 Google LLC",
    "postal": "94043",
    "timezone": "America\/Los_Angeles"
  },
  "error": ""
}
```

## Monitor Client Linux

시스템 모니터 클라이언트 스크립트입니다. <br>
CLI 환경에서 실행할 수 있습니다.

시스템 상태 정보를 수집하여 MONITOR_SERVER_QUERY_INTERVAL 간격으로 <br>
MONITOR_SERVER_ADDRESS 서버에 UDP 전송합니다. <br>

### 백그라운드 실행

```shell
sudo php -f monitor_client_linux.php &
```

### 메시지 형식 예시

```json
{
    "cpu_status": {
        "usage": [
            {
                "cpu": 0,
                "user": 66588,
                "system": 14861,
                "nice": 14657,
                "idle": 857622
            },
            {
                "cpu": 1,
                "user": 70427,
                "system": 18184,
                "nice": 13936,
                "idle": 852175
            },
            {
                "cpu": 2,
                "user": 70483,
                "system": 16764,
                "nice": 13757,
                "idle": 853918
            },
            {
                "cpu": 3,
                "user": 69235,
                "system": 17280,
                "nice": 13611,
                "idle": 855076
            }
        ]
    },
    "memory_status": {
        "mem_total": 16308136,
        "mem_free": 5171464,
        "cached": 3571068,
        "swap_total": 20502004,
        "swap_free": 20502004,
        "swap_cached": 0
    },
    "filesystem_statuses": [
        {
            "filesystem": "\/dev\/sda1",
            "size": 1044468,
            "used": 402640,
            "available": 641828,
            "mounted_on": "\/boot\/efi"
        },
        {
            "filesystem": "\/dev\/sda2",
            "size": 4186096,
            "used": 3070508,
            "available": 1115588,
            "mounted_on": "\/recovery"
        }
    ],
    "net_status": {
        "connected": false,
        "api_response": null
    },
    "time_info": {
        "time": 1706694025,
        "timezone": "Asia\/Tokyo\n",
        "uptime": 9627
    },
    "users": [
        "antibiotics",
        "root"
    ],
    "services": {
        "apache2": {
            "name": "apache2",
            "active": false,
            "pid": 0,
            "cpu": "",
            "memory": ""
        },
        "mysql": {
            "name": "mysql",
            "active": true,
            "pid": 1075,
            "cpu": "44.406s",
            "memory": "424.0M"
        },
        "postfix": {
            "name": "postfix",
            "active": true,
            "pid": 2176,
            "cpu": "1ms",
            "memory": ""
        },
        "ssh": {
            "name": "ssh",
            "active": true,
            "pid": 1024,
            "cpu": "29ms",
            "memory": "3.2M"
        },
        "ufw": {
            "name": "ufw",
            "active": true,
            "pid": 677,
            "cpu": "79ms",
            "memory": ""
        }
    },
    "interfaces": [
        {
            "name": "lo",
            "up": true,
            "addresses": [
                {
                    "address": "127.0.0.1",
                    "family": 2,
                    "netmask": "255.0.0.0"
                },
                {
                    "address": "::1",
                    "family": 10,
                    "netmask": "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
                }
            ],
            "tx_packets": 2020,
            "tx_bytes": 554709,
            "rx_packets": 2020,
            "rx_bytes": 554709
        },
        {
            "name": "enp4s0",
            "up": true,
            "addresses": [
                {
                    "address": "10.10.10.10",
                    "family": 2,
                    "netmask": "255.255.255.0"
                }
            ],
            "tx_packets": 326376,
            "tx_bytes": 48738176,
            "rx_packets": 1090312,
            "rx_bytes": 1534309968
        }
    ]
}
```