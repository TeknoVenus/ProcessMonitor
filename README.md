# Linux Process Monitor
Record linux process exec/exit events and produce a timeline of which processes ran.

Designed to help better understand what background processes are running and how long they take to execute.

## Build
```shell
$ mkdir build && cd build
$ cmake -DCMAKE_BUILD_TYPE=Release ../
$ make -j$(nproc)
```

## Run
Start by running ProcessMonitor as root, providing a duration to capture for (in seconds) and a file to save the results into. Note the output file will be a javascript file.
```shell
$ ./ProcessMonitor --duration 60 --output /tmp/processMonitor/results.js
```
Copy the generated output file to `<this-repo-dir>/results_gui/results.js` (must be called results.js for now)

Load the index.html file (Chrome works best) and a timeline of the observed processes should appear.

![screenshot of timeline](./docs/timeline.png)

Note it may take a few minutes for a timeline to load, especially for longer captures with lots of data (your browser may warn you the page is unresponsive, just allow it to continue - be patient!)

The tool will do it's best to work out the "true" command name - i.e. if the command is run under a specific interpreter (`sh -c ls -a`), the tool will work out the true command is actually `ls`.

### Timeline tips
* Hold `Ctrl` and scroll to zoom in/out
* Processes are grouped by their parent process
  * Only show specific parent processes using the filter dropdown
* Click on a process to view more information
* When zoomed out, some processes may be clustered together - shown by a number representing the number of processes in that cluster
  * Zoom in or double-click the cluster to see details!