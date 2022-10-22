# proc_exec notes

- Have the started command take the place of the main process and have Capmon
  run as the fork? This makes more sense if you still want to be able to do
  things in your main program. Makes it more like `bear` that just monitors in
  the background. Exit capmon when the main program exits?
