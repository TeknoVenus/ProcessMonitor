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

Copy this output file to `<repo-dir>/results_gui/results.js`

Load the index.html file - a timeline of the observed processes should appear.