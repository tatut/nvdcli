#!/bin/sh

./nvdcli q "score:>7" "match:liferay"
./nvdcli --output verbose show CVE-2020-28885 |grep baseScore
./nvdcli --output id q match:jackson match:2025
