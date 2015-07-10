#!/bin/bash 
if [ -d switchyard ]; then
  echo "Updating switchyard code"
  cd switchyard
  git pull
  cd ..
else
  echo "Cloning switchyard code"
  git clone https://github.com/jsommers/switchyard
fi
sudo pip3 install -q -r switchyard/requirements.txt
