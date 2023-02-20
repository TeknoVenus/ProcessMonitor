# Linux Process Monitor
Record processes exec/exit events and produce a timeline of which processes ran

## Build
```shell
$ mkdir build && cd build
$ cmake -DCMAKE_BUILD_TYPE=Release ../
```

## Run
Start by running ProcessMonitor, providing a duration to capture for (in seconds) and a file to save the results into
```shell
./ProcessMonitor --duration 60 --output /tmp/processMonitor/results.js
```
Press `Ctrl + C` to stop capturing data.

Copy the generated output file to `<this-repo-dir>/results_gui/results.js` (must be called results.js for now)

Load the index.html file - a timeline of the observed processes should appear.
