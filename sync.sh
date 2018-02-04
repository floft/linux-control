#!/bin/bash
rsync -av --info=progress2 --exclude=.git --exclude=run.sh \
    /home/garrett/Documents/Github/linux-control/ rpi:/srv/http/linux-control/
