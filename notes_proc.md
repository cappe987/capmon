# proc_exec notes

- Have the started command take the place of the main process and have Capmon
  run as the fork? This makes more sense if you still want to be able to do
  things in your main program. Makes it more like `bear` that just monitors in
  the background. Exit capmon when the main program exits?
  Probably not needed since child process shares I/O. Capmon will ignore SIGINT
  itself put pass it through to the child process.

- Assumes no zombie processes. When the initial root dies it stops. Other types
  of hand-offs also don't work. Once it is detached from the current session
  the parent pid changes and the pid tracking breaks. Capmon depends on
  tracking parent and child pid's.

- Firefox (and probably other programs) cannot be run *with* sudo. So you need to
  use capabilities to use capmon on it. Firefox doesn't work well anyways since
  it hands ownership to someone else.


- Make it so Capmon still supports the legacy mode of monitoring capabilities.
  Can be useful for the times when proc tracking cannot be used (eg. Firefox).
