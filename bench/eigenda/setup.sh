#!/bin/sh
echo "Downloading SRS resources"
if ! [ -f ./resources/g1.point ]; then
  echo "g1.point does not exist."
  echo "Downloading g1 point..."
  wget https://srs-mainnet.s3.amazonaws.com/kzg/g1.point --output-document=./resources/g1.point
else
  echo "g1.point already exists."
fi

if ! [ -f ./resources/g2.point ]; then
  echo "g2.point does not exist."
  echo "Downloading g2 point..."
  wget https://srs-mainnet.s3.amazonaws.com/kzg/g2.point --output-document=./resources/g2.point
else
  echo "g2.point already exists."
fi

if ! [ -f ./resources/g2.point.powerOf2 ]; then
  echo "g2.point.powerOf2 does not exist."
  echo "Downloading g2 point powerOf2..."
  wget https://srs-mainnet.s3.amazonaws.com/kzg/g2.point.powerOf2 --output-document=./resources/g2.point.powerOf2
else
  echo "g2.point.powerOf2 already exists."
fi
