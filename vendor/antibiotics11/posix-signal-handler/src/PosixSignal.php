<?php

namespace antibiotics11\PosixSignalHandler;

enum PosixSignal: int {

  /**
   * Hangup signal (SIGHUP)
   * Sent to a process when its controlling terminal is closed or the session leader exits.
   */
  case SIGHUP  = 1;

  /**
   * Interrupt signal (SIGINT)
   * Sent to a process by its controlling terminal when a user interrupts the process (typically Ctrl+C).
   */
  case SIGINT  = 2;

  /**
   * Quit signal (SIGQUIT)
   * Sent to a process by its controlling terminal when the user requests that the process quit (typically Ctrl+\).
   */
  case SIGQUIT = 3;

  /**
   * Illegal instruction signal
   * Sent to a process when it attempts to execute an illegal or undefined instruction.
   */
  case SIGILL  = 4;

  /**
   * Abort signal (SIGABRT)
   * Sent to a process to request abnormal termination.
   */
  case SIGABRT = 6;

  /**
   * Kill signal (SIGKILL)
   * Sent to a process to immediately terminate it. The process cannot catch or ignore this signal.
   */
  case SIGKILL = 9;

  /**
   * User-defined signal 1 (SIGUSR1)
   * Can be used by a process for application-specific purposes.
   */
  case SIGUSR1 = 10;

  /**
   * Segmentation violation signal (SIGSEGV)
   * Sent to a process when it accesses a memory location that is not allowed.
   */
  case SIGSEGV = 11;

  /**
   * User-defined signal 2 (SIGUSR2)
   * Can be used by a process for application-specific purposes.
   */
  case SIGUSR2 = 12;

  /**
   * Broken pipe signal (SIGPIPE)
   * Sent to a process when it attempts to write to a pipe without a process that reads from the other end.
   */
  case SIGPIPE = 13;

  /**
   * Alarm signal (SIGALRM)
   * Sent to a process when the timer set by the alarm() system call expires.
   */
  case SIGALRM = 14;

  /**
   * Termination Signal (SIGTERM)
   * Sent to a process to request termination.
   */
  case SIGTERM = 15;

  /**
   * Child process status changed signal (SIGCHLD)
   * Sent to a process when a child process terminates, is stopped, or resumes.
   */
  case SIGCHLD = 17;

  /**
   * Continue signal (SIGCONT)
   * Sent to a process to make it continue if it was stopped (e.g., by SIGSTOP).
   */
  case SIGCONT = 18;

  /**
   * Stop signal (SIGSTOP)
   * Sent to a process to halt it. The process cannot catch or ignore this signal.
   */
  case SIGSTOP = 19;

  /**
   * Terminal stop signal (SIGTSTP)
   * Sent to a process to request it to stop (suspend) itself.
   */
  case SIGTSTP = 20;

  /**
   * Terminal input signal (SIGTTIN)
   * Sent to a process when it attempts to read from the terminal while running in the background.
   */
  case SIGTTIN = 21;

  /**
   * Terminal output signal (SIGTTOU)
   * Sent to a process when it attempts to write to the terminal while running in the background.
   */
  case SIGTTOU = 22;

}
