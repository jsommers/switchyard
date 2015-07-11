#!/bin/bash

# assume we're running this from parent directory (within mininet)
cd www

# create a couple files for testing
echo '<html> <head><title>Test file 1</title></head> <body> sneaky crackers wuz here! </body> </html>' > 1.html
dd if=/dev/zero of=bigfile bs=1k count=100 2>&1 > /dev/null

if (( $# == 0 )) ; then
   port=80
else
   port=$1
fi

python3 -m http.server ${port} &

