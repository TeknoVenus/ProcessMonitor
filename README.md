# Linux Process Monitor
Record processes exec/exit events and produce a timeline of which processes ran

## Build
```shell
$ mkdir build && cd build
$ cmake -DCMAKE_BUILD_TYPE=Release ../
```

## Run
Start by running ProcessMonitor, redirecting stdout to a file - this will contain the results
```shell
./ProcessMonitor > /opt/results.js
```
Press `Ctrl + C` to stop capturing data.

Copy the generated output file to `<repo-dir>/results_gui/results.js` (must be called results.js for now)

Load the index.html file - a timeline of the observed processes should appear.
