#! /bin/bash

cd $(dirname "$0")

while [ 1 == 1 ]; do
	./bild_gruppen_arbeiter_static > /dev/null 2> /dev/null
	sleep 10
done
