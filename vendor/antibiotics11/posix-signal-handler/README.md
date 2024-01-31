# PosixSignalHandler

A utility class for handling POSIX signals in PHP applications.

## Requirements

- PHP 8.1 or higher
- <a href="https://www.php.net/manual/en/intro.pcntl.php">ext-pcntl</a>

## Usage

```php
require_once __DIR__ . "/src/PosixSignal.php";
require_once __DIR__ . "/src/PosixSignalHandler.php";

// Registering a custom handler for SIGINT (Ctrl+C)
PosixSignalHandler::addHandler(PosixSignal::SIGINT, function (): void {
  printf("\tCtrl+C pressed! Exiting...\r\n");
  exit(0);
});

```
