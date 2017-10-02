#! /bin/bash

###############################################
# update binary from Circle CI (master branch)
###############################################

cd $(dirname "$0")

pkill bild_gruppen_arbeiter_static # will stop bild_gruppen_arbeiter_static
cp -av bild_gruppen_arbeiter_static bild_gruppen_arbeiter_static__BACKUP
wget -O bild_gruppen_arbeiter_static 'https://circleci.com/api/v1/project/zoff99/ToxCam/latest/artifacts/0/$CIRCLE_ARTIFACTS/ubuntu_14_04_binaries/bild_gruppen_arbeiter_static?filter=successful&branch=master'
chmod u+rwx bild_gruppen_arbeiter_static
